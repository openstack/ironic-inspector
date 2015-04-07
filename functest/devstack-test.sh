#!/bin/bash

set -eux

INTROSPECTION_SLEEP=${INTROSPECTION_SLEEP:-30}
EXPECTED_CPU_ARCH=${EXPECTED_CPU_ARCH:-x86_64}
EXPECTED_CPUS=${EXPECTED_CPUS:-1}
EXPECTED_MIN_LOCAL_GB=${EXPECTED_MIN_LOCAL_GB:-1}
EXPECTED_MIN_MEMORY_MB=${EXPECTED_MIN_MEMORY_MB:-512}

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
done

for uuid in $nodes; do
    # TODO(dtantsur): use Ironic API instead
    openstack baremetal introspection start $uuid
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
done

echo "Validation passed"
