#!/bin/bash

set -eux

INTROSPECTION_SLEEP=${INTROSPECTION_SLEEP:-30}
export IRONIC_API_VERSION=${IRONIC_API_VERSION:-latest}
# Copied from devstack
PRIVATE_NETWORK_NAME=${PRIVATE_NETWORK_NAME:-"private"}

expected_cpus=$(openstack flavor show baremetal -f value -c vcpus)
expected_memory_mb=$(openstack flavor show baremetal -f value -c ram)
expected_cpu_arch=$(openstack flavor show baremetal -f value -c properties | sed "s/.*cpu_arch='\([^']*\)'.*/\1/")

disk_size=$(openstack flavor show baremetal -f value -c disk)
ephemeral_size=$(openstack flavor show baremetal -f value -c "OS-FLV-EXT-DATA:ephemeral")
expected_local_gb=$(($disk_size + $ephemeral_size))

ironic_url=$(keystone endpoint-get --service baremetal | tail -n +4 | head -n -1 | tr '|' ' ' | awk '{ print $2; }')
if [ -z "$ironic_url" ]; then
    echo "Cannot find Ironic URL"
    exit 1
fi

nodes=$(ironic node-list | tail -n +4 | head -n -1 | tr '|' ' ' | awk '{ print $1; }')
if [ -z "$nodes" ]; then
    echo "No nodes found in Ironic"
    exit 1
fi

for uuid in $nodes; do
    for p in cpus cpu_arch memory_mb local_gb; do
        ironic node-update $uuid remove properties/$p > /dev/null || true
    done
    ironic node-set-provision-state $uuid manage
done

for uuid in $nodes; do
    ironic node-set-provision-state $uuid inspect
done

current_nodes=$nodes
temp_nodes=
while true; do
    sleep $INTROSPECTION_SLEEP
    for uuid in $current_nodes; do
        finished=$(openstack baremetal introspection status $uuid -f value -c finished)
        if [ "$finished" = "True" ]; then
            error=$(openstack baremetal introspection status $uuid -f value -c error)
            if [ "$error" != "None" ]; then
                echo "Introspection for $uuid failed: $error"
                exit 1
            fi
        else
            temp_nodes="$temp_nodes $uuid"
        fi
    done
    if [ "$temp_nodes" = "" ]; then
        echo "Introspection done"
        break
    else
        current_nodes=$temp_nodes
        temp_nodes=
    fi
done

# NOTE(dtantsur): it's hard to get JSON field from Ironic client output, using
# HTTP API and JQ instead.
token=$(keystone token-get | grep ' id ' | tr '|' ' ' | awk '{ print $2; }')

function curl_ir {
    curl -H "X-Auth-Token: $token" -X $1 "$ironic_url/$2"
}

for uuid in $nodes; do
    node_json=$(curl_ir GET v1/nodes/$uuid)
    properties=$(echo $node_json | jq '.properties')

    echo Properties for $uuid: $properties
    if [ "$(echo $properties | jq -r '.cpu_arch')" != "$expected_cpu_arch" ]; then
        echo "Expected CPU architecture: $expected_cpu_arch"
        exit 1
    fi
    if [ "$(echo $properties | jq -r '.cpus')" != "$expected_cpus" ]; then
        echo "Expected number of CPUS: $expected_cpus"
        exit 1
    fi
    if [ "$(echo $properties | jq -r '.local_gb')" != "$expected_local_gb" ]; then
        echo "Expected disk: $expected_local_gb"
        exit 1
    fi
    if [ "$(echo $properties | jq -r '.memory_mb')" != "$expected_memory_mb" ]; then
        echo "Expected memory: $expected_memory_mb"
        exit 1
    fi

    for attempt in {1..12}; do
        node_json=$(curl_ir GET v1/nodes/$uuid)
        provision_state=$(echo $node_json | jq -r '.provision_state')

        if [ "$provision_state" != "manageable" ]; then
            if [ "$attempt" -eq 12 ]; then
                echo "Expected provision_state manageable, got $provision_state"
                exit 1
            fi
        else
            break
        fi
        sleep 10
    done

    ironic node-set-provision-state $uuid provide
done

echo "Wait until nova becomes aware of bare metal instances"

for attempt in {1..24}; do
    if [ $(nova hypervisor-stats | grep ' vcpus ' | head -n1 | awk '{ print $4; }') -ge $expected_cpus ]; then
        break
    elif [ "$attempt" -eq 24 ]; then
        echo "Timeout while waiting for nova hypervisor-stats"
        exit 1
    fi
    sleep 5
done

echo "Try nova boot for one instance"

image=$(glance image-list | grep ami | head -n1 | awk '{ print $4 }')
net_id=$(neutron net-list | egrep "$PRIVATE_NETWORK_NAME"'[^-]' | awk '{ print $2 }')
uuid=$(nova boot --flavor baremetal --nic net-id=$net_id --image $image testing | grep " id " | awk '{ print $4 }')

for attempt in {1..30}; do
    status=$(nova show $uuid | grep " status " | awk '{ print $4 }')
    if [ "$status" = "ERROR" ]; then
        echo "Instance failed to boot"
        # Some debug output
        nova show $uuid
        nova hypervisor-stats
        exit 1
    elif [ "$status" != "ACTIVE" ]; then
        if [ "$attempt" -eq 30 ]; then
            echo "Instance didn't become ACTIVE, status is $status"
            exit 1
        fi
    else
        break
    fi
    sleep 30
done

nova delete $uuid

echo "Validation passed"
