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
#   Dashboard (service "forensicnova-dashboard"):
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
# Repo synchronisation
# =============================================================================

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

forensicnova_register_dfir_service() {
    local public_url="http://${HOST_IP}:${FORENSICNOVA_PORT}"
    local region="${REGION_NAME:-RegionOne}"

    forensicnova_log "extra" \
        "registering '${FORENSICNOVA_SERVICE_NAME}' service in Keystone catalog (${public_url}, region ${region})"

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
# Dashboard — Idempotent building blocks
# =============================================================================

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
    local f
    for f in "$FORENSICNOVA_DASHBOARD_DIR"/forensicnova_dashboard/enabled/_*.py; do
        [[ -f "$f" ]] || continue
        local target="${HORIZON_LOCAL_ENABLED_DIR}/$(basename "$f")"
        sudo rm -f "$target"
    done
}

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

# =============================================================================
# Analyzer service (forensicnova-analyzer) — Volatility 3 + future MISP/YARA
# =============================================================================

FORENSICNOVA_ANALYZER_SYSTEMD_UNIT="devstack@forensicnova-analyzer.service"
FORENSICNOVA_ANALYZER_SYSTEMD_PATH="/etc/systemd/system/${FORENSICNOVA_ANALYZER_SYSTEMD_UNIT}"

fanalyzer_log() {
    local phase="$1"; shift
    echo "[ForensicNova-Analyzer][${phase}] $*"
}

# -----------------------------------------------------------------------------
# Idempotent building blocks
# -----------------------------------------------------------------------------

fanalyzer_install_python_deps() {
    fanalyzer_log "install" \
        "creating venv and installing Python deps in $FORENSICNOVA_ANALYZER_DIR/.venv-analyzer"
    python3 -m venv "$FORENSICNOVA_ANALYZER_DIR/.venv-analyzer"
    local venv_pip="$FORENSICNOVA_ANALYZER_DIR/.venv-analyzer/bin/pip"
    "$venv_pip" install --quiet --disable-pip-version-check --upgrade pip setuptools wheel
    # Pinned Volatility 3 version: 2.28.0 is the last release before the
    # 2026-06-07 plugin removal/rename window. Pinning protects the
    # 50-day thesis timeline from upstream churn.
    #
    # Optional Vol3 dependencies (yara-python, capstone, pycryptodome) are
    # required to unlock additional plugins beyond the base 91 of the bare
    # install. With these three installed, Vol3 exposes ~106 plugins
    # including credential dumpers (registry.hashdump, registry.lsadump,
    # registry.cachedump), EDR-bypass detectors (direct_system_calls,
    # indirect_system_calls), MFT scan (mftscan.MFTScan + ADS +
    # ResidentData), and the YARA scanner (vadyarascan). Without them
    # Vol3 silently hides the dependent plugins from `vol --help`.
    #
    #   yara-python   -> windows.vadyarascan.VadYaraScan,
    #                    linux.vmayarascan.VmaYaraScan
    #   capstone      -> windows.malware.direct_system_calls.*,
    #                    windows.malware.indirect_system_calls.*,
    #                    windows.mftscan.*
    #   pycryptodome  -> windows.registry.hashdump.Hashdump,
    #                    windows.registry.lsadump.Lsadump,
    #                    windows.registry.cachedump.Cachedump
    "$venv_pip" install --quiet --disable-pip-version-check \
        Flask \
        keystonemiddleware \
        python-swiftclient \
        python-keystoneclient \
        requests \
        yara-python \
        capstone \
        pycryptodome \
        "volatility3==2.28.0"
}

fanalyzer_write_config_file() {
    fanalyzer_log "post-config" \
        "writing config file ${FORENSICNOVA_ANALYZER_CONF_FILE}"
    sudo install -d -m 0755 -o "${STACK_USER}" -g "${STACK_USER}" \
        "${FORENSICNOVA_CONF_DIR}"
    sudo tee "${FORENSICNOVA_ANALYZER_CONF_FILE}" >/dev/null <<EOF
# Generated by ForensicNova DevStack plugin — DO NOT EDIT BY HAND.
# Source template: forensicnova_analyzer/etc/forensicnova-analyzer.conf.sample
[forensicnova_analyzer]
bind_host = ${FORENSICNOVA_ANALYZER_BIND_HOST}
bind_port = ${FORENSICNOVA_ANALYZER_PORT}
log_file = ${FORENSICNOVA_ANALYZER_LOG_FILE}
log_level = INFO
work_dir = ${FORENSICNOVA_ANALYZER_WORK_DIR}
jobs_dir = ${FORENSICNOVA_ANALYZER_JOBS_DIR}

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

[forensics]
project = ${FORENSICNOVA_PROJECT}
dfir_user = ${FORENSICNOVA_DFIR_USER}
EOF
    sudo chown "${STACK_USER}:${STACK_USER}" "${FORENSICNOVA_ANALYZER_CONF_FILE}"
    sudo chmod 0640 "${FORENSICNOVA_ANALYZER_CONF_FILE}"
}

fanalyzer_create_runtime_dirs() {
    fanalyzer_log "post-config" "creating runtime directories"
    sudo install -d -m 0755 -o "${STACK_USER}" -g "${STACK_USER}" \
        "${FORENSICNOVA_ANALYZER_WORK_DIR}" \
        "${FORENSICNOVA_ANALYZER_JOBS_DIR}" \
        "${FORENSICNOVA_ANALYZER_VOL3_CACHE}"
}

fanalyzer_install_systemd_unit() {
    fanalyzer_log "extra" "writing systemd unit ${FORENSICNOVA_ANALYZER_SYSTEMD_PATH}"
    local venv_python="${FORENSICNOVA_ANALYZER_DIR}/.venv-analyzer/bin/python"
    sudo tee "${FORENSICNOVA_ANALYZER_SYSTEMD_PATH}" >/dev/null <<EOF
[Unit]
Description=ForensicNova Analyzer — DFIR memory analysis service (Volatility 3)
Documentation=https://github.com/numdav/forensicnova
After=network-online.target devstack@forensicnova.service
Wants=network-online.target

[Service]
Type=simple
User=${STACK_USER}
Group=${STACK_USER}
WorkingDirectory=${FORENSICNOVA_ANALYZER_DIR}
Environment=PYTHONUNBUFFERED=1
Environment=PYTHONPATH=${FORENSICNOVA_ANALYZER_DIR}
Environment=FORENSICNOVA_ANALYZER_CONFIG=${FORENSICNOVA_ANALYZER_CONF_FILE}
Environment=FORENSICNOVA_DFIR_PASSWORD=${FORENSICNOVA_DFIR_PASSWORD}
Environment=XDG_CACHE_HOME=${FORENSICNOVA_ANALYZER_VOL3_CACHE}
ExecStart=${venv_python} -m forensicnova_analyzer.wsgi
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=forensicnova-analyzer

[Install]
WantedBy=multi-user.target
EOF
    sudo chmod 644 "${FORENSICNOVA_ANALYZER_SYSTEMD_PATH}"
    sudo systemctl daemon-reload
}

fanalyzer_register_service() {
    local public_url="http://${HOST_IP}:${FORENSICNOVA_ANALYZER_PORT}"
    local region="${REGION_NAME:-RegionOne}"
    fanalyzer_log "extra" \
        "registering '${FORENSICNOVA_ANALYZER_SERVICE_NAME}' service in Keystone catalog (${public_url}, region ${region})"

    if openstack service show "$FORENSICNOVA_ANALYZER_SERVICE_TYPE" >/dev/null 2>&1; then
        fanalyzer_log "extra" \
            "service '${FORENSICNOVA_ANALYZER_SERVICE_NAME}' already present — skipping create"
    else
        if ! openstack service create \
                --name "$FORENSICNOVA_ANALYZER_SERVICE_NAME" \
                --description "$FORENSICNOVA_ANALYZER_SERVICE_DESCRIPTION" \
                "$FORENSICNOVA_ANALYZER_SERVICE_TYPE" >/dev/null; then
            fanalyzer_log "extra" \
                "WARNING: could not create service '${FORENSICNOVA_ANALYZER_SERVICE_NAME}' — skipping endpoints"
            return 0
        fi
        fanalyzer_log "extra" \
            "service '${FORENSICNOVA_ANALYZER_SERVICE_NAME}' created (type=${FORENSICNOVA_ANALYZER_SERVICE_TYPE})"
    fi

    local iface existing
    for iface in public internal admin; do
        existing=$(openstack endpoint list \
            --service "$FORENSICNOVA_ANALYZER_SERVICE_TYPE" \
            --interface "$iface" \
            -f value -c ID 2>/dev/null)
        if [[ -n "$existing" ]]; then
            fanalyzer_log "extra" \
                "endpoint ${iface} already present (${existing}) — skipping"
        else
            if openstack endpoint create \
                --region "$region" \
                "$FORENSICNOVA_ANALYZER_SERVICE_TYPE" \
                "$iface" \
                "$public_url" >/dev/null 2>&1; then
                fanalyzer_log "extra" \
                    "endpoint ${iface} created -> ${public_url}"
            else
                fanalyzer_log "extra" \
                    "WARNING: could not create ${iface} endpoint (non-fatal)"
            fi
        fi
    done
}

fanalyzer_unregister_service() {
    fanalyzer_log "unstack" \
        "removing endpoints + service '${FORENSICNOVA_ANALYZER_SERVICE_NAME}' from Keystone catalog"
    local ep_id
    for ep_id in $(openstack endpoint list \
            --service "$FORENSICNOVA_ANALYZER_SERVICE_TYPE" \
            -f value -c ID 2>/dev/null); do
        openstack endpoint delete "$ep_id" >/dev/null 2>&1 || true
    done
    openstack service delete "$FORENSICNOVA_ANALYZER_SERVICE_TYPE" >/dev/null 2>&1 || true
}

fanalyzer_start_service() {
    fanalyzer_log "extra" "enabling and starting ${FORENSICNOVA_ANALYZER_SYSTEMD_UNIT}"
    sudo systemctl enable --now "${FORENSICNOVA_ANALYZER_SYSTEMD_UNIT}"
    sleep 2
    if systemctl is-active --quiet "${FORENSICNOVA_ANALYZER_SYSTEMD_UNIT}"; then
        fanalyzer_log "extra" "${FORENSICNOVA_ANALYZER_SYSTEMD_UNIT} is active"
        if command -v curl >/dev/null 2>&1; then
            local probe
            probe=$(curl -fsS --max-time 3 \
                "http://127.0.0.1:${FORENSICNOVA_ANALYZER_PORT}/health" 2>/dev/null || true)
            if [[ -n "$probe" ]]; then
                fanalyzer_log "extra" "health probe OK: $probe"
            else
                fanalyzer_log "extra" \
                    "WARNING: health probe empty — service up but /health did not respond"
            fi
        fi
    else
        fanalyzer_log "extra" \
            "WARNING: ${FORENSICNOVA_ANALYZER_SYSTEMD_UNIT} is not active — inspect 'journalctl -u ${FORENSICNOVA_ANALYZER_SYSTEMD_UNIT}'"
    fi
}

# -----------------------------------------------------------------------------
# Analyzer — Phase functions
# -----------------------------------------------------------------------------

install_forensicnova_analyzer() {
    fanalyzer_log "install" "phase: install"
    fanalyzer_install_python_deps
}

configure_forensicnova_analyzer() {
    fanalyzer_log "post-config" "phase: post-config"
    if [[ -z "$FORENSICNOVA_DFIR_PASSWORD" ]]; then
        fanalyzer_log "post-config" \
            "ERROR: FORENSICNOVA_DFIR_PASSWORD is unset. Set it in local.conf."
        return 1
    fi
    fanalyzer_create_runtime_dirs
    fanalyzer_write_config_file
}

init_forensicnova_analyzer() {
    fanalyzer_log "extra" "phase: extra"
    fanalyzer_register_service
    fanalyzer_install_systemd_unit
    fanalyzer_start_service
}

stop_forensicnova_analyzer() {
    fanalyzer_log "unstack" "phase: unstack"
    if [[ -f "${FORENSICNOVA_ANALYZER_SYSTEMD_PATH}" ]] \
       || systemctl list-unit-files --no-legend 2>/dev/null \
           | grep -q "^${FORENSICNOVA_ANALYZER_SYSTEMD_UNIT}"; then
        fanalyzer_log "unstack" "stopping ${FORENSICNOVA_ANALYZER_SYSTEMD_UNIT}"
        sudo systemctl stop "${FORENSICNOVA_ANALYZER_SYSTEMD_UNIT}" 2>/dev/null || true
        sudo systemctl disable "${FORENSICNOVA_ANALYZER_SYSTEMD_UNIT}" 2>/dev/null || true
    else
        fanalyzer_log "unstack" "no systemd unit to stop"
    fi
    fanalyzer_unregister_service
}

cleanup_forensicnova_analyzer() {
    fanalyzer_log "clean" "phase: clean"
    sudo systemctl stop "${FORENSICNOVA_ANALYZER_SYSTEMD_UNIT}" 2>/dev/null || true
    sudo systemctl disable "${FORENSICNOVA_ANALYZER_SYSTEMD_UNIT}" 2>/dev/null || true
    if [[ -f "${FORENSICNOVA_ANALYZER_SYSTEMD_PATH}" ]]; then
        fanalyzer_log "clean" "removing ${FORENSICNOVA_ANALYZER_SYSTEMD_PATH}"
        sudo rm -f "${FORENSICNOVA_ANALYZER_SYSTEMD_PATH}"
        sudo systemctl daemon-reload
    fi
    sudo rm -rf "$FORENSICNOVA_ANALYZER_WORK_DIR"
    sudo rm -f "$FORENSICNOVA_ANALYZER_CONF_FILE"
    rm -rf "$FORENSICNOVA_ANALYZER_DIR/.venv-analyzer"
}

# -----------------------------------------------------------------------------
# Analyzer dispatcher
# -----------------------------------------------------------------------------

if is_service_enabled forensicnova-analyzer; then
    if [[ "$1" == "stack" ]]; then
        case "$2" in
            install)      install_forensicnova_analyzer ;;
            post-config)  configure_forensicnova_analyzer ;;
            extra)        init_forensicnova_analyzer ;;
            *)            : ;;
        esac
    elif [[ "$1" == "unstack" ]]; then
        stop_forensicnova_analyzer
    elif [[ "$1" == "clean" ]]; then
        cleanup_forensicnova_analyzer
    fi
fi
