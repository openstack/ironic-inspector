#!/bin/bash

set -eux

# Import help functions
IRONIC_INSPECTOR_DEVSTACK_PLUGIN_DIR=$(cd $(dirname "${BASH_SOURCE:-$0}") && pwd)
source ${IRONIC_INSPECTOR_DEVSTACK_PLUGIN_DIR}/exercise_common.sh

# this exercise destroys BM nodes
# precaution measures
assert_sudo
hook=$(get_ini $IRONIC_INSPECTOR_CONF_FILE processing node_not_found_hook) || {
    echo "Please, enable node_not_found_hook in processing section of inspector.conf"
    exit 1
}

if [ -z "$hook" ] ; then
   echo "Please, provide a value for node_not_found_hook in processing section of inspector.conf"
   exit 1
fi

nodes=$(node_list)
if [ -z "$nodes" ]; then
    echo "No nodes found in Ironic"
    exit 1
fi

# Choose one ironic node for discover
discover_uuid=
for uuid in $nodes; do
    provision_state=$(node_attribute $uuid provision_state)
    if [[ $provision_state = "available" ]] || [[ $provision_state = "enroll" ]] ; then
        discover_uuid=$uuid
        break
    fi
done

if [ -z "$discover_uuid" ] ; then
    echo "No nodes in available provisioning state"
    exit 1
fi

# Get node details before delete it
node_name=$(node_attribute $discover_uuid name)
node_driver=$(node_attribute $discover_uuid driver)
node_mac=$(node_mac $discover_uuid)
declare -A driver_info
node_driver_info $discover_uuid driver_info

# create temporary discovery rule
discovery_rule=$(mktemp)
node_discovery_rule $node_name $node_driver driver_info > "$discovery_rule"

echo "Purging introspection rules; importing custom rules"
openstack baremetal introspection rule purge
openstack baremetal introspection rule import "$discovery_rule"

# get virsh node uuid
virsh_uuid=$(node_to_virsh_uuid $discover_uuid)

# delete&rediscover node
echo "Delete Ironic node $discover_uuid (and ports) for discovery"
ironic node-delete $discover_uuid
wait_for 120 ! assert_mac_blacklisted $node_mac

# Start vm's for discover
echo "booting virsh $virsh_uuid domain to be discovered"
sudo virsh start $virsh_uuid

echo "waiting for discovered node to appear"
discovered_node=
wait_for 900 node_exists $node_name discovered_node

echo "waiting for introspection to finish"
wait_for 900 assert_node_introspection_status $discovered_node

# validate discovery result
validate_node_flavor $discovered_node baremetal
assert_equal $node_driver $(node_attribute $discovered_node driver)
validate_node_driver_info $discovered_node driver_info

rm -f $discovery_rule

echo "Validation passed"
