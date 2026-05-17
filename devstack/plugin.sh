#!/usr/bin/env bash
# ForensicNova DevStack plugin
# https://github.com/numdav/forensicnova
#
# Lifecycle phases wired in this file:
#
#   Backend (service "forensicnova"):
#     stack pre-install   -> preinstall_forensicnova  (system packages)
#     stack install       -> install_forensicnova     (python venv + pip deps)
#     stack post-config   -> configure_forensicnova   (dirs, conf file, openrc, secret_key)
#     stack extra         -> init_forensicnova        (keystone identity, swift,
#                                                      service catalog, systemd)
#     unstack             -> stop_forensicnova        (stop unit, drop service catalog)
#     clean               -> cleanup_forensicnova     (remove unit + data)
#
#   Dashboard (service "forensicnova-dashboard", Feature 4):
#     stack install       -> install_forensicnova_dashboard      (pip install -e
#                                                                 into Horizon venv)
#     stack post-config   -> configure_forensicnova_dashboard    (copy enabled/,
#                                                                 collectstatic, compress)
#     stack extra         -> init_forensicnova_dashboard         (restart Horizon)
#     unstack             -> stop_forensicnova_dashboard         (remove enabled/)
#     clean               -> cleanup_forensicnova_dashboard      (remove enabled/ +
#                                                                 uninstall pkg)

FORENSICNOVA_PLUGIN_DIR=$(readlink -f "$(dirname "${BASH_SOURCE[0]}")")
# shellcheck disable=SC1091
source "${FORENSICNOVA_PLUGIN_DIR}/settings"

FORENSICNOVA_SYSTEMD_UNIT="devstack@forensicnova.service"
FORENSICNOVA_SYSTEMD_PATH="/etc/systemd/system/${FORENSICNOVA_SYSTEMD_UNIT}"

# =============================================================================
# Logging helpers
# =============================================================================

forensicnova_marker() {
    local phase="$1"
    local msg="${2:-marker}"
    echo "[ForensicNova][${phase}] ${msg}"
}

forensicnova_log() {
    local phase="$1"; shift
    echo "[ForensicNova][${phase}] $*"
}

# Dashboard-specific log prefix to make journalctl filtering easier.
fdash_log() {
    local phase="$1"; shift
    echo "[ForensicNova-Dashboard][${phase}] $*"
}

# =============================================================================
# Repo synchronisation (Feature 3.5+)
# =============================================================================

# Sync /opt/stack/forensicnova to the latest origin/main commit.
#
# Why this exists:
#   DevStack does not re-pull plugin repositories on subsequent stack.sh
#   runs when the plugin directory already exists. The default RECLONE
#   flag (False) means stack.sh trusts whatever code is on disk under
#   /opt/stack/<plugin>. That breaks our iteration loop: we push to
#   GitHub from /home/davide/projects/forensicnova, then re-stack, then
#   discover the deployed code is stale because /opt/stack/forensicnova
#   was last cloned days ago.
#
# What this function does:
#   At pre-install time, if the deploy directory is a git checkout,
#   fetch origin/main and hard-reset to it. The deployed code is now
#   guaranteed to match the latest pushed commit.
#
# Safety:
#   - Skipped on first stack (no .git directory yet — DevStack will clone
#     fresh from local.conf's enable_plugin URL).
#   - Hard reset is intentional: any uncommitted change in the deploy
#     tree is overwritten. The whole point of the plugin model is that
#     /opt/stack/forensicnova is a read-only mirror of origin/main; manual
#     edits there are an anti-pattern and must not be preserved.
#   - On fetch/reset failure (network down, GitHub rate-limit, etc.) the
#     function logs a WARNING and continues with the on-disk code instead
#     of aborting the stack. Better stale-but-running than no-stack-at-all.
#
# Monorepo note (Feature 4):
#   This function syncs the WHOLE repo. Since the Horizon dashboard now
#   lives in the same repo (under forensicnova_dashboard/), a single
#   git reset --hard re-aligns both backend AND dashboard code in one
#   shot. No additional sync logic is needed for the dashboard.
forensicnova_sync_repo() {
    if [[ ! -d "${FORENSICNOVA_DIR}/.git" ]]; then
        forensicnova_log "pre-install" \
            "no .git in ${FORENSICNOVA_DIR} — first-time clone will be done by DevStack, skipping sync"
        return 0
    fi

    local before
    before=$(sudo -u "$STACK_USER" git -C "$FORENSICNOVA_DIR" log -1 --oneline 2>/dev/null || echo "unknown")
    forensicnova_log "pre-install" "current deploy HEAD: ${before}"

    if ! sudo -u "$STACK_USER" git -C "$FORENSICNOVA_DIR" fetch --quiet origin main 2>&1; then
        forensicnova_log "pre-install" \
            "WARNING: git fetch failed; continuing with on-disk code (${before})"
        return 0
    fi

    if ! sudo -u "$STACK_USER" git -C "$FORENSICNOVA_DIR" reset --hard --quiet origin/main 2>&1; then
        forensicnova_log "pre-install" \
            "WARNING: git reset failed; continuing with on-disk code (${before})"
        return 0
    fi

    local after
    after=$(sudo -u "$STACK_USER" git -C "$FORENSICNOVA_DIR" log -1 --oneline 2>/dev/null || echo "unknown")
    if [[ "$before" == "$after" ]]; then
        forensicnova_log "pre-install" "deploy already up to date (${after})"
    else
        forensicnova_log "pre-install" "synced ${before}  ->  ${after}"
    fi
}

# =============================================================================
# Backend — Idempotent building blocks
# =============================================================================

forensicnova_ensure_dirs() {
    forensicnova_log "post-config" "ensuring runtime directories"
    local d
    for d in "$FORENSICNOVA_WORK_DIR" "$FORENSICNOVA_LOG_DIR" \
             "$FORENSICNOVA_CONF_DIR" "$FORENSICNOVA_JOBS_DIR"; do
        sudo mkdir -p "$d"
        sudo chown -R "$STACK_USER:$STACK_USER" "$d"
        sudo chmod 750 "$d"
    done
}

# Generate the Flask session signing key if not already present.
# IDEMPOTENT: preserving the existing key across ./unstack.sh + ./stack.sh
# keeps active dashboard sessions valid.
forensicnova_ensure_secret_key() {
    local secret_key_file="${FORENSICNOVA_WORK_DIR}/secret_key"
    if [[ -f "$secret_key_file" ]]; then
        forensicnova_log "post-config" \
            "secret_key already present at $secret_key_file — preserving existing sessions"
    else
        forensicnova_log "post-config" \
            "generating new Flask secret_key at $secret_key_file"
        openssl rand -hex 32 | sudo tee "$secret_key_file" >/dev/null
    fi
    sudo chown "$STACK_USER:$STACK_USER" "$secret_key_file"
    sudo chmod 600 "$secret_key_file"
}

# Keystone identity artifacts: role, project, user, role assignments.
# Also grants dfir-tester the 'admin' role on EVERY existing project
# so the forensic analyst can read metadata of any tenant's VMs.
#
# This admin-on-all-projects grant is the pragmatic prototype workaround.
# A least-privilege Nova policy.yaml override (the deferred Feature 3)
# is incompatible with Nova 2026.2's enforce_new_defaults=True and is
# documented as a thesis-roadmap item.
forensicnova_ensure_identity() {
    forensicnova_log "extra" "ensuring Keystone identity artifacts"

    get_or_create_role "$FORENSICNOVA_ROLE"

    get_or_create_project "$FORENSICNOVA_PROJECT" default \
        "$FORENSICNOVA_PROJECT_DESCRIPTION"

    get_or_create_user "$FORENSICNOVA_DFIR_USER" \
        "$FORENSICNOVA_DFIR_PASSWORD" default
    get_or_add_user_project_role "$FORENSICNOVA_ROLE" \
        "$FORENSICNOVA_DFIR_USER" "$FORENSICNOVA_PROJECT"
    get_or_add_user_project_role "member" \
        "$FORENSICNOVA_DFIR_USER" "$FORENSICNOVA_PROJECT"
    get_or_add_user_project_role "admin" \
        "$FORENSICNOVA_DFIR_USER" "$FORENSICNOVA_PROJECT"

    # Cross-tenant admin role: grant 'admin' on every existing project.
    forensicnova_log "extra" \
        "granting 'admin' role on all projects to ${FORENSICNOVA_DFIR_USER}"
    local project
    for project in $(openstack project list -c Name -f value 2>/dev/null); do
        case "$project" in
            service)
                continue
                ;;
        esac
        get_or_add_user_project_role "admin" \
            "$FORENSICNOVA_DFIR_USER" "$project" || \
            forensicnova_log "extra" \
                "WARNING: could not add admin role on project '$project' (non-fatal)"
    done
}

# Ensure both the main forensic container AND the segments container that
# SLO uploads (Feature 2) need. The segments container hosts dump segments
# named '<dump_object_name>/seg-NNNN'; Swift treats it as an ordinary
# container, but by convention we keep it separate from the main one to
# clearly distinguish forensic artefacts (manifests, JSON reports, simple
# uploads) from raw segments that have no standalone meaning.
forensicnova_ensure_container() {
    local main_container="$FORENSICNOVA_SWIFT_CONTAINER"
    local segments_container="${FORENSICNOVA_SWIFT_CONTAINER}_segments"
    forensicnova_log "extra" \
        "ensuring Swift containers '${main_container}' and '${segments_container}' in project '${FORENSICNOVA_PROJECT}'"
    (
        export OS_USERNAME="$FORENSICNOVA_DFIR_USER"
        export OS_PASSWORD="$FORENSICNOVA_DFIR_PASSWORD"
        export OS_PROJECT_NAME="$FORENSICNOVA_PROJECT"
        export OS_USER_DOMAIN_ID=default
        export OS_PROJECT_DOMAIN_ID=default
        local cont
        for cont in "$main_container" "$segments_container"; do
            openstack container show "$cont" >/dev/null 2>&1 \
                || openstack container create "$cont" >/dev/null
        done
    )
}

# Feature 3.5 — register ForensicNova as a first-class OpenStack service
# in the Keystone catalog.
#
# Creates one service entry of type ${FORENSICNOVA_SERVICE_TYPE} and three
# endpoints (public / internal / admin), all pointing at the Flask service
# on http://${HOST_IP}:${FORENSICNOVA_PORT}. This is what lets the Horizon
# dashboard (Feature 4) discover the API through the catalog rather than
# hard-coding host:port.
#
# Idempotency:
#   - the service entry is created only if 'openstack service show
#     <type>' fails (no existing service of that type);
#   - each endpoint is created only if 'openstack endpoint list' shows no
#     existing endpoint of that interface for our service, so a re-run on
#     a live cloud does not produce duplicates.
#   Note: a full ./unstack.sh + ./stack.sh rebuilds the Keystone DB from
#   scratch, so on a normal restack this function always starts clean.
forensicnova_register_dfir_service() {
    local public_url="http://${HOST_IP}:${FORENSICNOVA_PORT}"
    local region="${REGION_NAME:-RegionOne}"

    forensicnova_log "extra" \
        "registering '${FORENSICNOVA_SERVICE_NAME}' service in Keystone catalog (${public_url}, region ${region})"

    # Idempotent service creation: 'openstack service create' has no
    # --or-show flag (unlike project/user/role create), so we must
    # check-then-create explicitly. 'openstack service show <type>'
    # exits 0 if a service of that type already exists, 1 otherwise.
    if openstack service show "$FORENSICNOVA_SERVICE_TYPE" >/dev/null 2>&1; then
        forensicnova_log "extra" \
            "service '${FORENSICNOVA_SERVICE_NAME}' already present — skipping create"
    else
        if ! openstack service create \
                --name "$FORENSICNOVA_SERVICE_NAME" \
                --description "$FORENSICNOVA_SERVICE_DESCRIPTION" \
                "$FORENSICNOVA_SERVICE_TYPE" >/dev/null; then
            forensicnova_log "extra" \
                "WARNING: could not create service '${FORENSICNOVA_SERVICE_NAME}' — skipping endpoints"
            return 0
        fi
        forensicnova_log "extra" \
            "service '${FORENSICNOVA_SERVICE_NAME}' created (type=${FORENSICNOVA_SERVICE_TYPE})"
    fi

    local iface existing
    for iface in public internal admin; do
        existing=$(openstack endpoint list \
            --service "$FORENSICNOVA_SERVICE_TYPE" \
            --interface "$iface" \
            -f value -c ID 2>/dev/null)
        if [[ -n "$existing" ]]; then
            forensicnova_log "extra" \
                "endpoint ${iface} already present (${existing}) — skipping"
        else
            if openstack endpoint create \
                --region "$region" \
                "$FORENSICNOVA_SERVICE_TYPE" \
                "$iface" \
                "$public_url" >/dev/null 2>&1; then
                forensicnova_log "extra" \
                    "endpoint ${iface} created -> ${public_url}"
            else
                forensicnova_log "extra" \
                    "WARNING: could not create ${iface} endpoint (non-fatal)"
            fi
        fi
    done
    forensicnova_log "extra" "service catalog registration complete"
}

# Feature 3.5 — remove the ForensicNova service + endpoints from the
# Keystone catalog. Best-effort: during ./unstack.sh Keystone may already
# be shutting down, so every failure is logged as a warning and ignored.
forensicnova_unregister_dfir_service() {
    forensicnova_log "unstack" \
        "removing '${FORENSICNOVA_SERVICE_NAME}' from Keystone catalog (best-effort)"

    local iface ep_id
    for iface in public internal admin; do
        ep_id=$(openstack endpoint list \
            --service "$FORENSICNOVA_SERVICE_TYPE" \
            --interface "$iface" \
            -f value -c ID 2>/dev/null)
        if [[ -n "$ep_id" ]]; then
            if openstack endpoint delete "$ep_id" >/dev/null 2>&1; then
                forensicnova_log "unstack" "endpoint ${iface} (${ep_id}) deleted"
            else
                forensicnova_log "unstack" \
                    "WARNING: could not delete endpoint ${ep_id} (ignored)"
            fi
        fi
    done

    if openstack service delete "$FORENSICNOVA_SERVICE_TYPE" >/dev/null 2>&1; then
        forensicnova_log "unstack" "service '${FORENSICNOVA_SERVICE_NAME}' deleted"
    else
        forensicnova_log "unstack" \
            "no service to delete, or Keystone unavailable (ignored)"
    fi
}

forensicnova_write_config() {
    forensicnova_log "post-config" "writing $FORENSICNOVA_CONF_FILE"
    sudo tee "$FORENSICNOVA_CONF_FILE" >/dev/null <<EOF
# ForensicNova plugin configuration
# Generated by devstack/plugin.sh — regenerated on every stack.sh run.
# DO NOT EDIT — changes will be overwritten.

[DEFAULT]
bind_host = ${FORENSICNOVA_BIND_HOST}
bind_port = ${FORENSICNOVA_PORT}
work_dir = ${FORENSICNOVA_WORK_DIR}
log_dir = ${FORENSICNOVA_LOG_DIR}

[keystone]
auth_url = http://${HOST_IP}/identity
region_name = ${REGION_NAME:-RegionOne}
forensic_role = ${FORENSICNOVA_ROLE}

[keystone_authtoken]
www_authenticate_uri = http://${HOST_IP}/identity
auth_url = http://${HOST_IP}/identity
auth_type = password
project_domain_id = default
user_domain_id = default
project_name = admin
username = admin
password = ${ADMIN_PASSWORD}
delay_auth_decision = true
interface = public

[swift]
container = ${FORENSICNOVA_SWIFT_CONTAINER}
slo_segment_size_bytes = ${FORENSICNOVA_SLO_SEGMENT_SIZE}

[forensics]
project = ${FORENSICNOVA_PROJECT}
dfir_user = ${FORENSICNOVA_DFIR_USER}

[libvirt]
uri = qemu:///system

[jobs]
jobs_dir = ${FORENSICNOVA_JOBS_DIR}
EOF
    sudo chown "$STACK_USER:$STACK_USER" "$FORENSICNOVA_CONF_FILE"
    sudo chmod 640 "$FORENSICNOVA_CONF_FILE"
}

forensicnova_write_openrc() {
    forensicnova_log "post-config" "writing $FORENSICNOVA_OPENRC"
    cat > "$FORENSICNOVA_OPENRC" <<EOF
#!/usr/bin/env bash
# ForensicNova — openrc for ${FORENSICNOVA_DFIR_USER}
# Generated by devstack/plugin.sh. Do not edit manually.
export OS_AUTH_URL=http://${HOST_IP}/identity
export OS_USERNAME=${FORENSICNOVA_DFIR_USER}
export OS_PASSWORD='${FORENSICNOVA_DFIR_PASSWORD}'
export OS_PROJECT_NAME=${FORENSICNOVA_PROJECT}
export OS_PROJECT_DOMAIN_ID=default
export OS_USER_DOMAIN_ID=default
export OS_IDENTITY_API_VERSION=3
export OS_AUTH_TYPE=password
export OS_REGION_NAME=${REGION_NAME:-RegionOne}
EOF
    chmod 600 "$FORENSICNOVA_OPENRC"
}

forensicnova_install_python_deps() {
    forensicnova_log "install" \
        "creating venv and installing Python deps in $FORENSICNOVA_DIR/.venv"
    python3 -m venv "$FORENSICNOVA_DIR/.venv"
    local venv_pip="$FORENSICNOVA_DIR/.venv/bin/pip"
    "$venv_pip" install --quiet --disable-pip-version-check --upgrade pip setuptools wheel
    "$venv_pip" install --quiet --disable-pip-version-check \
        Flask \
        Flask-WTF \
        reportlab \
        python-swiftclient \
        python-keystoneclient \
        python-novaclient \
        python-glanceclient \
        keystonemiddleware \
        requests \
        libvirt-python
}

forensicnova_install_systemd_unit() {
    forensicnova_log "extra" "writing systemd unit ${FORENSICNOVA_SYSTEMD_PATH}"
    local venv_python="${FORENSICNOVA_DIR}/.venv/bin/python"
    sudo tee "${FORENSICNOVA_SYSTEMD_PATH}" >/dev/null <<EOF
[Unit]
Description=ForensicNova — DFIR memory acquisition service
Documentation=https://github.com/numdav/forensicnova
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${STACK_USER}
Group=${STACK_USER}
WorkingDirectory=${FORENSICNOVA_DIR}
Environment=PYTHONUNBUFFERED=1
Environment=PYTHONPATH=${FORENSICNOVA_DIR}
Environment=FORENSICNOVA_CONFIG=${FORENSICNOVA_CONF_FILE}
Environment=FORENSICNOVA_DFIR_PASSWORD=${FORENSICNOVA_DFIR_PASSWORD}
ExecStart=${venv_python} -m app.wsgi
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=forensicnova

[Install]
WantedBy=multi-user.target
EOF
    sudo chmod 644 "${FORENSICNOVA_SYSTEMD_PATH}"
    sudo systemctl daemon-reload
}

forensicnova_start_service() {
    forensicnova_log "extra" "enabling and starting ${FORENSICNOVA_SYSTEMD_UNIT}"
    sudo systemctl enable --now "${FORENSICNOVA_SYSTEMD_UNIT}"
    sleep 2
    if systemctl is-active --quiet "${FORENSICNOVA_SYSTEMD_UNIT}"; then
        forensicnova_log "extra" "${FORENSICNOVA_SYSTEMD_UNIT} is active"
        if command -v curl >/dev/null 2>&1; then
            local probe
            probe=$(curl -fsS --max-time 3 \
                "http://127.0.0.1:${FORENSICNOVA_PORT}/health" 2>/dev/null || true)
            if [[ -n "$probe" ]]; then
                forensicnova_log "extra" "health probe OK: $probe"
            else
                forensicnova_log "extra" \
                    "WARNING: health probe empty — service up but /health did not respond"
            fi
        fi
    else
        forensicnova_log "extra" \
            "WARNING: ${FORENSICNOVA_SYSTEMD_UNIT} is not active — inspect 'journalctl -u ${FORENSICNOVA_SYSTEMD_UNIT}'"
    fi
}

# =============================================================================
# Backend — Phase functions
# =============================================================================

preinstall_forensicnova() {
    forensicnova_marker "pre-install"
    forensicnova_sync_repo
    if ! command -v virsh >/dev/null 2>&1; then
        forensicnova_log "pre-install" \
            "WARNING: virsh not found — memory acquisition requires libvirt on the compute node"
    else
        forensicnova_log "pre-install" "virsh available: $(command -v virsh)"
    fi
    if ! dpkg -s python3-venv libvirt-dev pkg-config >/dev/null 2>&1; then
        forensicnova_log "pre-install" "installing system dependencies (python3-venv, libvirt-dev, pkg-config)"
        sudo apt-get install -y python3-venv libvirt-dev pkg-config
    fi
}

install_forensicnova() {
    forensicnova_marker "install"
    forensicnova_install_python_deps
}

configure_forensicnova() {
    forensicnova_marker "post-config"
    if [[ -z "$FORENSICNOVA_DFIR_PASSWORD" ]]; then
        forensicnova_log "post-config" \
            "ERROR: FORENSICNOVA_DFIR_PASSWORD is unset. Set it in local.conf."
        return 1
    fi
    forensicnova_ensure_dirs
    forensicnova_ensure_secret_key
    forensicnova_write_config
    forensicnova_write_openrc
    forensicnova_log "post-config" "configuration completed successfully"
}

init_forensicnova() {
    forensicnova_marker "extra"
    forensicnova_ensure_identity
    forensicnova_ensure_container
    forensicnova_register_dfir_service
    forensicnova_install_systemd_unit
    forensicnova_start_service
    forensicnova_log "extra" "init completed"
}

stop_forensicnova() {
    forensicnova_marker "unstack"
    if [[ -f "${FORENSICNOVA_SYSTEMD_PATH}" ]] \
       || systemctl list-unit-files --no-legend 2>/dev/null \
           | grep -q "^${FORENSICNOVA_SYSTEMD_UNIT}"; then
        forensicnova_log "unstack" "stopping ${FORENSICNOVA_SYSTEMD_UNIT}"
        sudo systemctl stop "${FORENSICNOVA_SYSTEMD_UNIT}" 2>/dev/null || true
        sudo systemctl disable "${FORENSICNOVA_SYSTEMD_UNIT}" 2>/dev/null || true
    else
        forensicnova_log "unstack" "no systemd unit to stop"
    fi
    forensicnova_unregister_dfir_service
}

cleanup_forensicnova() {
    forensicnova_marker "clean"
    sudo systemctl stop "${FORENSICNOVA_SYSTEMD_UNIT}" 2>/dev/null || true
    sudo systemctl disable "${FORENSICNOVA_SYSTEMD_UNIT}" 2>/dev/null || true
    if [[ -f "${FORENSICNOVA_SYSTEMD_PATH}" ]]; then
        forensicnova_log "clean" "removing ${FORENSICNOVA_SYSTEMD_PATH}"
        sudo rm -f "${FORENSICNOVA_SYSTEMD_PATH}"
        sudo systemctl daemon-reload
    fi
    sudo rm -rf "$FORENSICNOVA_WORK_DIR" "$FORENSICNOVA_LOG_DIR" "$FORENSICNOVA_CONF_DIR"
    rm -f "$FORENSICNOVA_OPENRC"
    rm -rf "$FORENSICNOVA_DIR/.venv"
}

# =============================================================================
# Dashboard (Feature 4) — Idempotent building blocks
# =============================================================================
#
# The dashboard is a Horizon (Django) plugin. It is installed into Horizon's
# venv (NOT the backend venv) via `pip install -e`, and it registers its
# panels by dropping _9NNN_*.py files into Horizon's `local/enabled/` dir.
# Horizon auto-discovers them at Django startup.

# Probe for Horizon's Python interpreter / pip. DevStack-deployed Horizon
# typically uses /opt/stack/data/venv (the shared services venv); we fall
# back to /usr/local/bin and /usr/bin only as a safety net.
FORENSICNOVA_DASHBOARD_PIP=""

fdash_locate_horizon_pip() {
    local candidates=(
        "/opt/stack/data/venv/bin/pip"
        "/usr/local/bin/pip3"
        "/usr/bin/pip3"
    )
    local p
    for p in "${candidates[@]}"; do
        if [[ -x "$p" ]]; then
            FORENSICNOVA_DASHBOARD_PIP="$p"
            fdash_log "install" "using pip at ${FORENSICNOVA_DASHBOARD_PIP}"
            return 0
        fi
    done
    fdash_log "install" "ERROR: no pip found in expected locations"
    return 1
}

# `pip install -e` operates on the directory containing setup.cfg/setup.py.
# In the monorepo this is FORENSICNOVA_DIR (== FORENSICNOVA_DASHBOARD_DIR).
# The setup.cfg [options.packages.find] include=forensicnova_dashboard*
# rule ensures only the dashboard package is installed, NOT the backend's
# app/ package — which lives in the same directory but belongs to a
# separate venv and must stay out of Horizon's Python path.
fdash_install_package() {
    fdash_log "install" "installing forensicnova-dashboard (editable) into Horizon's venv"
    fdash_locate_horizon_pip || return 1
    sudo "$FORENSICNOVA_DASHBOARD_PIP" install --quiet --disable-pip-version-check \
        -e "$FORENSICNOVA_DASHBOARD_DIR"
}

fdash_uninstall_package() {
    fdash_locate_horizon_pip 2>/dev/null || return 0
    fdash_log "clean" "uninstalling forensicnova-dashboard from Horizon's venv"
    sudo "$FORENSICNOVA_DASHBOARD_PIP" uninstall -y forensicnova-dashboard 2>/dev/null || true
}

# Drop the _9NNN_*.py registration files into Horizon's local/enabled/
# directory. Horizon scans this dir at Django startup and imports every
# matching file: each one registers a Dashboard, PanelGroup or Panel.
fdash_install_enabled_files() {
    fdash_log "post-config" "copying enabled/ files to ${HORIZON_LOCAL_ENABLED_DIR}"
    sudo mkdir -p "$HORIZON_LOCAL_ENABLED_DIR"
    local f
    for f in "$FORENSICNOVA_DASHBOARD_DIR"/forensicnova_dashboard/enabled/_*.py; do
        [[ -f "$f" ]] || continue
        local target="${HORIZON_LOCAL_ENABLED_DIR}/$(basename "$f")"
        sudo install -m 644 "$f" "$target"
        fdash_log "post-config" "installed $(basename "$f")"
    done
}

fdash_remove_enabled_files() {
    fdash_log "clean" "removing forensicnova-dashboard enabled/ files"
    sudo rm -f "${HORIZON_LOCAL_ENABLED_DIR}"/_9000_dfir.py
    sudo rm -f "${HORIZON_LOCAL_ENABLED_DIR}"/_9010_dfir_forensics_panelgroup.py
    sudo rm -f "${HORIZON_LOCAL_ENABLED_DIR}"/_9020_dfir_acquisitions.py
    sudo rm -f "${HORIZON_LOCAL_ENABLED_DIR}"/_9030_dfir_new_acquisition.py
}

# Horizon serves static assets (CSS, JS) from a Django collectstatic dir.
# Adding a new dashboard introduces new templates (and possibly static
# files); we run collectstatic + compress so Apache picks them up.
# Failure here is non-fatal: Horizon still runs, only the new dashboard's
# assets might 404 until the next successful stack.
fdash_collectstatic_and_compress() {
    fdash_log "post-config" "running collectstatic + compress for Horizon"
    local manage_py="${DEST}/horizon/manage.py"
    if [[ ! -f "$manage_py" ]]; then
        fdash_log "post-config" "WARNING: manage.py not found at ${manage_py} — skipping"
        return 0
    fi
    local python_bin
    if [[ -x "/opt/stack/data/venv/bin/python" ]]; then
        python_bin="/opt/stack/data/venv/bin/python"
    else
        python_bin="$(command -v python3)"
    fi
    sudo -u "$STACK_USER" "$python_bin" "$manage_py" collectstatic \
        --noinput >/dev/null 2>&1 \
        || fdash_log "post-config" "collectstatic returned non-zero (ignored)"
    sudo -u "$STACK_USER" "$python_bin" "$manage_py" compress \
        --force >/dev/null 2>&1 \
        || fdash_log "post-config" "compress returned non-zero (ignored)"
}

# Horizon runs inside Apache (mod_wsgi). The DevStack systemd unit
# `devstack@horizon.service` is cosmetic on modern DevStack: the actual
# process is Apache. We try systemctl restart first (works on some
# layouts), fall back to `service apache2 restart`.
fdash_restart_horizon() {
    local unit="devstack@horizon.service"
    fdash_log "extra" "restarting ${unit} (or apache2)"
    sudo systemctl restart "$unit" 2>/dev/null || \
        sudo service apache2 restart 2>/dev/null || \
        fdash_log "extra" "WARNING: could not restart Horizon (no systemd unit, no apache2)"
    sleep 2
}

# =============================================================================
# Dashboard — Phase functions
# =============================================================================

install_forensicnova_dashboard() {
    fdash_log "install" "phase: install"
    fdash_install_package
}

configure_forensicnova_dashboard() {
    fdash_log "post-config" "phase: post-config"
    fdash_install_enabled_files
    fdash_collectstatic_and_compress
}

init_forensicnova_dashboard() {
    fdash_log "extra" "phase: extra"
    fdash_restart_horizon
}

stop_forensicnova_dashboard() {
    fdash_log "unstack" "phase: unstack"
    # Horizon is restarted by the main DevStack unstack flow; we just
    # remove our enabled/ entries so that if a partial unstack happens,
    # Horizon comes back clean of stale DFIR panels.
    fdash_remove_enabled_files
}

cleanup_forensicnova_dashboard() {
    fdash_log "clean" "phase: clean"
    fdash_remove_enabled_files
    fdash_uninstall_package
}

# =============================================================================
# Dispatcher
# =============================================================================
#
# Two independent service flags drive two independent lifecycles. Each
# block is guarded by `is_service_enabled`, so the operator can disable
# either side from local.conf with `disable_service`.

# --- Backend dispatcher ---
if is_service_enabled forensicnova; then
    if [[ "$1" == "stack" ]]; then
        case "$2" in
            pre-install)  preinstall_forensicnova ;;
            install)      install_forensicnova ;;
            post-config)  configure_forensicnova ;;
            extra)        init_forensicnova ;;
            *)            : ;;
        esac
    elif [[ "$1" == "unstack" ]]; then
        stop_forensicnova
    elif [[ "$1" == "clean" ]]; then
        cleanup_forensicnova
    fi
fi

# --- Dashboard dispatcher (Feature 4) ---
if is_service_enabled forensicnova-dashboard; then
    if [[ "$1" == "stack" ]]; then
        case "$2" in
            install)      install_forensicnova_dashboard ;;
            post-config)  configure_forensicnova_dashboard ;;
            extra)        init_forensicnova_dashboard ;;
            *)            : ;;
        esac
    elif [[ "$1" == "unstack" ]]; then
        stop_forensicnova_dashboard
    elif [[ "$1" == "clean" ]]; then
        cleanup_forensicnova_dashboard
    fi
fi
