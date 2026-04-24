#!/usr/bin/env bash
# ForensicNova DevStack plugin
# https://github.com/numdav/forensicnova
#
# Lifecycle phases wired in this file:
#   stack pre-install   -> preinstall_forensicnova  (system packages)
#   stack install       -> install_forensicnova     (python venv + pip deps)
#   stack post-config   -> configure_forensicnova   (dirs, conf file, openrc, secret_key)
#   stack extra         -> init_forensicnova        (keystone, swift, systemd)
#   unstack             -> stop_forensicnova        (stop systemd unit)
#   clean               -> cleanup_forensicnova     (remove unit + data)

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

# =============================================================================
# Idempotent building blocks
# =============================================================================

forensicnova_ensure_dirs() {
    forensicnova_log "post-config" "ensuring runtime directories"
    local d
    for d in "$FORENSICNOVA_WORK_DIR" "$FORENSICNOVA_LOG_DIR" "$FORENSICNOVA_CONF_DIR"; do
        sudo mkdir -p "$d"
        sudo chown -R "$STACK_USER:$STACK_USER" "$d"
        sudo chmod 750 "$d"
    done
}

# Generate the Flask session signing key if not already present.
# IDEMPOTENT: preserving the existing key across ./unstack.sh + ./stack.sh
# keeps active dashboard sessions valid (rotating the key would force all
# logged-in analysts to re-authenticate after every restack).
# A fresh key is generated only when the file is missing (first stack, or
# after ./clean.sh which removes the entire work_dir).
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
    # Always fix ownership and perms — belt-and-suspenders for files created
    # manually by an operator before the plugin took over.
    sudo chown "$STACK_USER:$STACK_USER" "$secret_key_file"
    sudo chmod 600 "$secret_key_file"
}

# Keystone identity artifacts: role, project, user, role assignments.
# Also grants dfir-tester the 'admin' role on EVERY existing project
# so the forensic analyst can read metadata of any tenant's VMs
# (needed by Nova/Glance API calls in app/forensics/nova_metadata.py).
# Read-only cross-tenant visibility is the DFIR analyst contract.
forensicnova_ensure_identity() {
    forensicnova_log "extra" "ensuring Keystone identity artifacts"

    # Custom role for forensic analysts.
    get_or_create_role "$FORENSICNOVA_ROLE"

    # Dedicated project for DFIR artifacts.
    get_or_create_project "$FORENSICNOVA_PROJECT" default \
        "$FORENSICNOVA_PROJECT_DESCRIPTION"

    # Test user and base role assignments in the 'forensics' project.
    get_or_create_user "$FORENSICNOVA_DFIR_USER" \
        "$FORENSICNOVA_DFIR_PASSWORD" default
    get_or_add_user_project_role "$FORENSICNOVA_ROLE" \
        "$FORENSICNOVA_DFIR_USER" "$FORENSICNOVA_PROJECT"
    get_or_add_user_project_role "member" \
        "$FORENSICNOVA_DFIR_USER" "$FORENSICNOVA_PROJECT"
    get_or_add_user_project_role "admin" \
        "$FORENSICNOVA_DFIR_USER" "$FORENSICNOVA_PROJECT"

    # Cross-tenant admin role: grant 'admin' on every existing project
    # so dfir-tester can query Nova/Glance metadata for any VM regardless
    # of its owner project.  Idempotent via get_or_add_user_project_role.
    forensicnova_log "extra" \
        "granting 'admin' role on all projects to ${FORENSICNOVA_DFIR_USER}"
    local project
    for project in $(openstack project list -c Name -f value 2>/dev/null); do
        # Skip service and internal projects we don't want the DFIR user in.
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
    forensicnova_log "extra" \
        "ensuring Swift container '$FORENSICNOVA_SWIFT_CONTAINER' in project '$FORENSICNOVA_PROJECT'"
    (
        export OS_USERNAME="$FORENSICNOVA_DFIR_USER"
        export OS_PASSWORD="$FORENSICNOVA_DFIR_PASSWORD"
        export OS_PROJECT_NAME="$FORENSICNOVA_PROJECT"
        export OS_USER_DOMAIN_ID=default
        export OS_PROJECT_DOMAIN_ID=default
        openstack container show "$FORENSICNOVA_SWIFT_CONTAINER" >/dev/null 2>&1 \
            || openstack container create "$FORENSICNOVA_SWIFT_CONTAINER" >/dev/null
    )
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
region_name = RegionOne
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

[libvirt]
uri = qemu:///system
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
export OS_REGION_NAME=RegionOne
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
# Phase functions
# =============================================================================

preinstall_forensicnova() {
    forensicnova_marker "pre-install"
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
    forensicnova_install_systemd_unit
    forensicnova_start_service
    forensicnova_log "extra" "FASE 3 init completed"
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
# Dispatcher
# =============================================================================

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
