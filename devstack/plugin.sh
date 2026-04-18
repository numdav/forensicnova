#!/usr/bin/env bash
# ==============================================================================
# ForensicNova — DevStack plugin dispatcher
# ==============================================================================
# This script is invoked multiple times during stack/unstack/clean lifecycles.
# DevStack passes the lifecycle ($1) and the phase ($2) as arguments, e.g.:
#     plugin.sh stack pre-install
#     plugin.sh stack install
#     plugin.sh stack post-config
#     plugin.sh stack extra
#     plugin.sh unstack
#     plugin.sh clean
#
# STAGE 2a NOTE: this is a SKELETON. Each phase only logs a marker line.
#                Real logic will be added in stage 2b once loading is verified.
# ==============================================================================

# Preserve existing xtrace setting, then quiet it down for our source block
_XTRACE_FORENSICNOVA=$(set +o | grep xtrace)
set +o xtrace

# ------------------------------------------------------------------------------
# Marker helper: prints a clearly greppable line into DevStack's log stream
# so we can confirm every phase is invoked and in which order.
# ------------------------------------------------------------------------------
function forensicnova_marker {
    local phase="$1"
    echo "[ForensicNova][${phase}] marker: reached phase '${phase}' at $(date -u +%Y-%m-%dT%H:%M:%SZ)"
}

# ------------------------------------------------------------------------------
# Phase functions (empty skeletons — to be implemented in stage 2b)
# ------------------------------------------------------------------------------

function preinstall_forensicnova {
    forensicnova_marker "pre-install"
    # TODO stage 2b: apt install libvirt-clients python3-libvirt python3-venv
}

function install_forensicnova {
    forensicnova_marker "install"
    # TODO stage 2b: create venv, pip install Flask, ReportLab, python-swiftclient,
    #                python-keystoneclient, keystonemiddleware
    #                pip install -e $FORENSICNOVA_DIR
}

function configure_forensicnova {
    forensicnova_marker "post-config"
    # TODO stage 2b: ensure Keystone role '$FORENSICNOVA_ROLE' exists
    #                create Swift container '$FORENSICNOVA_SWIFT_CONTAINER'
    #                write /etc/forensicnova/forensicnova.conf
    #                create $FORENSICNOVA_WORK_DIR and $FORENSICNOVA_LOG_DIR
}

function init_forensicnova {
    forensicnova_marker "extra"
    # TODO stage 2b: register and start systemd unit 'devstack@forensicnova'
    #                exposing Flask API on ${FORENSICNOVA_BIND_HOST}:${FORENSICNOVA_PORT}
}

function stop_forensicnova {
    forensicnova_marker "unstack"
    # TODO stage 2b: stop systemd unit 'devstack@forensicnova'
}

function cleanup_forensicnova {
    forensicnova_marker "clean"
    # TODO stage 2b: remove $FORENSICNOVA_WORK_DIR, $FORENSICNOVA_LOG_DIR,
    #                /etc/forensicnova/, and the Swift container contents
}

# ------------------------------------------------------------------------------
# Main dispatcher — DevStack drives us via $1 (lifecycle) and $2 (phase)
# ------------------------------------------------------------------------------
if [[ "$1" == "stack" ]]; then
    case "$2" in
        pre-install)
            preinstall_forensicnova
            ;;
        install)
            install_forensicnova
            ;;
        post-config)
            configure_forensicnova
            ;;
        extra)
            init_forensicnova
            ;;
        *)
            # Ignore other phases we don't need (e.g. test-config, source)
            ;;
    esac
elif [[ "$1" == "unstack" ]]; then
    stop_forensicnova
elif [[ "$1" == "clean" ]]; then
    cleanup_forensicnova
fi

# Restore xtrace setting
$_XTRACE_FORENSICNOVA
