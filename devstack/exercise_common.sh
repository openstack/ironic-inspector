#!/bin/bash

IRONIC_INSPECTOR_CONF_FILE="/etc/ironic-inspector/inspector.conf"

function assert_sudo {
    # make sure sudo works in non-interactive mode
    if ! sudo -n true ; then
        echo "ERROR: sudo doesn't work"
        return 1
    fi
}

function token_issue {
    openstack token issue -f value -c id
}

function endpoint_url {
    local endpoint=${1:?endpoint not specified}
    openstack endpoint show ${endpoint} -f value -c adminurl
}

function auth_curl {
    local url=${1:?url not specified} ; shift
    local method=${1:-GET} ; shift
    local token=$(token_issue)

    curl -H "X-Auth-Token: $token" -X ${method} ${url} ${@}
}

function curl_ironic {
    local url=${1:?url not specified} ; shift
    local method=${1:-GET} ; shift

    auth_curl "$(endpoint_url baremetal)/${url#/}" ${method} ${@}
}

function node_list {
    openstack baremetal list -f value -c UUID
}

function node_attribute {
    local uuid=${1:?uuid not specified}
    local attribute=${2:?attribute not specified}

    openstack baremetal show ${uuid} -f value -c ${attribute}
}

function json_query {
    local data_name=${1:?data variable name not specified}; shift
    local var_name=${1:?variable name not specified}; shift
    local key=${1:?key not specified}; shift
    local query=$@

    local tmp=$(jq ${query} <<<${!data_name})
    eval ${var_name}[${key}]=${tmp}
}

function virsh_domains {

    # Id    Name                           State
    #----------------------------------------------------
    # -     baremetalbrbm_0                shut off
    #
    sudo -n virsh list --all | tail -n+3 | awk '{print $2;}' | head -n-1
}

function virsh_domain_mac {
    local domain=${1:?domain not specified}

    # ....
    #    <mac address='52:54:00:df:96:0c'/>
    # ....
    sudo -n virsh dumpxml $domain | grep 'mac address' | cut -d \' -f2
}

function node_mac {
    local uuid=${1:?uuid not specified}

    # +--------------------------------------+-------------------+
    # | UUID                                 | Address           |
    # +--------------------------------------+-------------------+
    # | 4d734b98-bae9-43a7-ba27-8dbdce2b0bf1 | 52:54:00:df:96:0c |
    # +--------------------------------------+-------------------+
    ironic node-port-list $uuid | tail -n+4 | head -n+1 | head -1 | tr -d \| | awk '{print $2;}'
}

function node_to_virsh_uuid {
    local uuid=${1:?uuid not specified}
    local node_mac=$(node_attribute $uuid mac_address)
    local map
    local node
    local domain

    declare -A map

    for node in $(node_list) ; do
        map[$(node_mac $node)]=$node
    done

    for domain in $(virsh_domains) ; do
        if [[ ${map[$(virsh_domain_mac $domain)]} = $uuid ]] ; then
            echo $domain
            return
        fi
    done
    return 1
}

function node_exists {
    local query=${1:?query not specified}
    local result_name=${2}

    for node in $(node_list) ; do
        if [ "${node}" == "${query}" ] || [ $(node_attribute $node name) == "${query}" ] ; then
            if [ -n "$result_name" ] ; then
                eval $result_name=$node
            fi
            return
        fi
    done
    return 1
}

function flavor_expand {
    local flavor=${1:?flavor not specified}
    local var_name=${2:?variable name not specified}

    eval $var_name[vcpus]=$(openstack flavor show ${flavor} -f value -c vcpus)
    eval $var_name[ram]=$(openstack flavor show ${flavor} -f value -c ram)
    eval $var_name[cpu_arch]=$(openstack flavor show ${flavor} -f value -c properties | sed "s/.*cpu_arch='\([^']*\)'.*/\1/")
    eval $var_name[disk]=$(openstack flavor show ${flavor} -f value -c disk)
    eval $var_name[ephemeral]=$(openstack flavor show ${flavor} -f value -c "OS-FLV-EXT-DATA:ephemeral")
    eval $var_name[local_gb]=$(($var_name[disk] + $var_name[ephemeral]))

}

function assert_last {
    local code=${1:?code not specified}
    local expected=${2:-0}
    local message=${3:-}

    if [ ${code} -ne ${expected} ] ; then
        if [ -n "${message}" ] ; then
            echo "${message}"
        fi
        return 1
    fi
}

function assert_equal {
    local lvalue=${1:?lvalue not specified}
    local rvalue=${2:?rvalue not specified}
    local message=${3:-}

    [ "${lvalue}" == "${rvalue}" ] || assert_last ${?} 0 "${message}" || return ${?}
}

function assert_equal_arrays {
    local lvalue_name=${1:?lvalue name not specified}
    local rvalue_name=${2:?rvalue name not specified}
    local lvalue
    local rvalue
    local keys
    local key

    eval keys=\${!${lvalue_name}[@]}
    for key in ${keys} ; do
        eval lvalue=\${$lvalue_name[$key]}
        eval rvalue=\${$rvalue_name[$key]}
        assert_equal $lvalue $rvalue "$key: $lvalue != $rvalue" || return ${?}
    done
    eval keys=\${!${rvalue_name}[@]}
    for key in ${keys} ; do
        eval lvalue=\${$lvalue_name[$key]}
        eval rvalue=\${$rvalue_name[$key]}
        assert_equal $lvalue $rvalue "$key: $lvalue != $rvalue" || return ${?}
    done
}

function assert_mac_blacklisted {
    local mac=${1:?mac not specified}

    sudo -n iptables -L ironic-inspector | grep -iq "${mac}" && return
    return 1
}

function assert_node_introspection_status {
    local node=${1:?uuid not specified}
    local finished_query=${2:-True}
    local error_query=${3:-None}
    local finished=$(openstack baremetal introspection status $node -f value -c finished)
    local error=$(openstack baremetal introspection status $node -f value -c error)

    assert_equal ${finished_query} ${finished} || return ${?}
    assert_equal ${error_query} ${error} || return ${?}
}

function node_discovery_rule {
    local node_name=${1:?node name not specified}
    local node_driver=${2:?driver not specified}
    local driver_info_name=${3:?driver info name not specified}
    local keys
    local key
    local value

    cat <<EOF
[
    {
        "description": "${node_name} discovery rule",
        "actions": [
            {"action": "set-attribute", "path": "/name",
             "value": "${node_name}"},
            {"action": "set-attribute", "path": "/driver",
             "value": "${node_driver}"}
EOF

    eval keys=\${!${driver_info_name}[@]}
    for key in ${keys} ; do
        eval value=\${${driver_info_name}[${key}]}
        cat <<EOF
            , {"action": "set-attribute", "path": "/driver_info/${key}",
             "value": "${value}"}
EOF
    done

cat <<EOF

        ],
        "conditions": [
            {"op": "eq", "field": "data://auto_discovered", "value": true}
        ]
    }
]
EOF
}

function validate_node_flavor {
    local node=${1:?uuid not specified}
    local flavor=${2:-baremetal}
    local json_data
    local expected
    local actual
    local key

    declare -A expected
    declare -A actual

    flavor_expand ${flavor} expected

    json_data=$(curl_ironic /v1/nodes/${node})

    for key in cpu_arch cpus local_gb memory_mb ; do
        json_query json_data actual ${key} -r ".properties.${key}"
    done

    assert_equal ${expected[cpu_arch]} ${actual[cpu_arch]} "unexpected cpu_arch: ${actual[cpu_arch]}"
    assert_equal ${expected[ram]} ${actual[memory_mb]} "unexpected memory: ${actual[memory_mb]}"
    assert_equal ${expected[vcpus]} ${actual[cpus]} "unexpected cpus: ${actual[cpus]}"
    assert_equal ${expected[local_gb]} ${actual[local_gb]} "unexpected local gb: ${actual[local_gb]}"
}

function node_driver_info {
    local node=${1:?uuid not specified}
    local var_name=${2:?var name not specified}
    local node_json=$(curl_ironic /v1/nodes/${node})
    local key

    for key in ssh_address ssh_virt_type ssh_port ssh_username ssh_key_filename deploy_kernel deploy_ramdisk ; do
        json_query node_json $var_name $key -r ".driver_info.$key"
    done
}

function validate_node_driver_info {
    local node=${1:?uuid not specified}
    local expected_var_name=${2:?expected var name not specified}
    local actual
    declare -A actual

    node_driver_info ${node} actual

    assert_equal_arrays $expected_var_name actual
}

function get_ini {
    local file=${1:?file not specified}
    local section=${2:?section not specified}
    local option=${3:?option not specified}

    cat <<_GET_INI | python -
import ConfigParser
cp = ConfigParser.ConfigParser()
cp.read("$file")
assert "$section" in cp.sections(), '$section not in $file'
assert "$option" in cp.options("$section"), '$option not in $file:$section'
print cp.get("$section", "$option")
_GET_INI
}

function wait_for {
    local timeout=${1:?timeout required}; shift
    local start_time=$(date +"%s")

    echo "waiting for ${@}; timeout: ${timeout}"
    while [ $(( start_time + timeout)) -ge $(date +"%s") ] && ! eval "${@}" ; do
        sleep ${wait_sleep:-3}
    done

    if [ $(( start_time + timeout )) -lt $(date +"%s") ] ; then
        echo "timeout reached (elapsed time: $(( $(date +"%s") - start_time )))"
        return 1
    fi
}
