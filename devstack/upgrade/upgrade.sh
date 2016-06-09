#!/usr/bin/env bash
## based on Ironic/devstack/upgrade/upgrade.sh

# ``upgrade-inspector``

echo "*********************************************************************"
echo "Begin $0"
echo "*********************************************************************"

# Clean up any resources that may be in use
cleanup() {
    set +o errexit

    echo "*********************************************************************"
    echo "ERROR: Abort $0"
    echo "*********************************************************************"

    # Kill ourselves to signal any calling process
    trap 2; kill -2 $$
}

trap cleanup SIGHUP SIGINT SIGTERM

# Keep track of the grenade directory
RUN_DIR=$(cd $(dirname "$0") && pwd)

# Source params
source $GRENADE_DIR/grenaderc

# Import common functions
source $GRENADE_DIR/functions

# This script exits on an error so that errors don't compound and you see
# only the first error that occurred.
set -o errexit

# Upgrade Inspector
# =================

# Duplicate some setup bits from target DevStack
source $TARGET_DEVSTACK_DIR/stackrc
source $TARGET_DEVSTACK_DIR/lib/tls
source $TARGET_DEVSTACK_DIR/lib/nova
source $TARGET_DEVSTACK_DIR/lib/neutron-legacy
source $TARGET_DEVSTACK_DIR/lib/apache
source $TARGET_DEVSTACK_DIR/lib/keystone
source $TARGET_DEVSTACK_DIR/lib/database

# Inspector relies on couple of Ironic variables
source $TARGET_RELEASE_DIR/ironic/devstack/lib/ironic

# Keep track of the DevStack directory
INSPECTOR_DEVSTACK_DIR=$(cd $(dirname "$0")/.. && pwd)
INSPECTOR_PLUGIN=$INSPECTOR_DEVSTACK_DIR/plugin.sh
source $INSPECTOR_PLUGIN

# Print the commands being run so that we can see the command that triggers
# an error.  It is also useful for following allowing as the install occurs.
set -o xtrace

initialize_database_backends

function is_nova_migration {
    # Determine whether we're "upgrading" from another compute driver
    _ironic_old_driver=$(source $BASE_DEVSTACK_DIR/functions; source $BASE_DEVSTACK_DIR/localrc; echo $VIRT_DRIVER)
    [ "$_ironic_old_driver" != "ironic" ]
}

# Duplicate all required devstack setup that is needed before starting
# Inspector during a sideways upgrade, where we are migrating from an
# devstack environment without Inspector.
function init_inspector {
    # We need to source credentials here but doing so in the gate will unset
    # HOST_IP.
    local tmp_host_ip=$HOST_IP
    source $TARGET_DEVSTACK_DIR/openrc admin admin
    HOST_IP=$tmp_host_ip
    IRONIC_BAREMETAL_BASIC_OPS="True"
    $TARGET_DEVSTACK_DIR/tools/install_prereqs.sh
    recreate_database ironic_inspector utf8
    $INSPECTOR_PLUGIN stack install
    $INSPECTOR_PLUGIN stack post-config
    $INSPECTOR_PLUGIN stack extra
}

function wait_for_keystone {
    if ! wait_for_service $SERVICE_TIMEOUT ${KEYSTONE_AUTH_URI}/v$IDENTITY_API_VERSION/; then
        die $LINENO "keystone did not start"
    fi
}

# Save current config files for posterity
if  [[ -d $IRONIC_INSPECTOR_CONF_DIR ]] && [[ ! -d $SAVE_DIR/etc.inspector ]] ; then
    cp -pr $IRONIC_INSPECTOR_CONF_DIR $SAVE_DIR/etc.inspector
fi

stack_install_service ironic-inspector

if [[ "$IRONIC_INSPECTOR_MANAGE_FIREWALL" == "True" ]]; then
    stack_install_service ironic-inspector-dhcp
fi


# FIXME(milan): using Ironic's detection; not sure whether it's needed
# If we are sideways upgrading and migrating from a base deployed with
# VIRT_DRIVER=fake, we need to run Inspector install, config and init
# code from devstack.
if is_nova_migration ; then
    init_inspector
fi

sync_inspector_database

# calls upgrade inspector for specific release
upgrade_project ironic-inspector $RUN_DIR $BASE_DEVSTACK_BRANCH $TARGET_DEVSTACK_BRANCH


start_inspector

if [[ "$IRONIC_INSPECTOR_MANAGE_FIREWALL" == "True" ]]; then
    start_inspector_dhcp
fi

# Don't succeed unless the services come up
ensure_services_started ironic-inspector
ensure_logs_exist ironic-inspector

if [[ "$IRONIC_INSPECTOR_MANAGE_FIREWALL" == "True" ]]; then
    ensure_services_started dnsmasq
    ensure_logs_exist ironic-inspector-dhcp
fi

set +o xtrace
echo "*********************************************************************"
echo "SUCCESS: End $0"
echo "*********************************************************************"
