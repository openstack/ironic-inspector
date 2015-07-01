#!/bin/bash

set -eux

INTROSPECTION_SLEEP=${INTROSPECTION_SLEEP:-30}
EXPECTED_CPU_ARCH=${EXPECTED_CPU_ARCH:-x86_64}
EXPECTED_CPUS=${EXPECTED_CPUS:-1}
EXPECTED_MIN_LOCAL_GB=${EXPECTED_MIN_LOCAL_GB:-1}
EXPECTED_MIN_MEMORY_MB=${EXPECTED_MIN_MEMORY_MB:-512}

export IRONIC_API_VERSION=${IRONIC_API_VERSION:-latest}

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
    # FIXME(dtantsur): virtual machines PXE often behaves weirdly when a lot of
    # machines DHCP at the same time, inserting sleep helps. It does not affect
    # bare metal environment AFAIK.
    sleep 5
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
    if [ "$(echo $properties | jq -r '.cpu_arch')" != "$EXPECTED_CPU_ARCH" ]; then
        echo "Expected $EXPECTED_CPU_ARCH"
        exit 1
    fi
    if [ "$(echo $properties | jq -r '.cpus')" != "$EXPECTED_CPUS" ]; then
        echo "Expected $EXPECTED_CPUS"
        exit 1
    fi
    if [ "$(echo $properties | jq -r '.local_gb')" -lt "$EXPECTED_MIN_LOCAL_GB" ]; then
        echo "Expected at least $EXPECTED_MIN_LOCAL_GB"
        exit 1
    fi
    if [ "$(echo $properties | jq -r '.memory_mb')" -lt "$EXPECTED_MIN_MEMORY_MB" ]; then
        echo "Expected at least $EXPECTED_MIN_MEMORY_MB"
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
done

echo "Validation passed"
