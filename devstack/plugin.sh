IRONIC_INSPECTOR_DEBUG=${IRONIC_INSPECTOR_DEBUG:-True}
IRONIC_INSPECTOR_DIR=$DEST/ironic-inspector
IRONIC_INSPECTOR_DATA_DIR=$DATA_DIR/ironic-inspector
IRONIC_INSPECTOR_BIN_DIR=$(get_python_exec_prefix)
IRONIC_INSPECTOR_BIN_FILE=$IRONIC_INSPECTOR_BIN_DIR/ironic-inspector
IRONIC_INSPECTOR_DBSYNC_BIN_FILE=$IRONIC_INSPECTOR_BIN_DIR/ironic-inspector-dbsync
IRONIC_INSPECTOR_CONF_DIR=${IRONIC_INSPECTOR_CONF_DIR:-/etc/ironic-inspector}
IRONIC_INSPECTOR_CONF_FILE=$IRONIC_INSPECTOR_CONF_DIR/inspector.conf
IRONIC_INSPECTOR_CMD="$IRONIC_INSPECTOR_BIN_FILE --config-file $IRONIC_INSPECTOR_CONF_FILE"
IRONIC_INSPECTOR_DHCP_CONF_FILE=$IRONIC_INSPECTOR_CONF_DIR/dnsmasq.conf
IRONIC_INSPECTOR_ROOTWRAP_CONF_FILE=$IRONIC_INSPECTOR_CONF_DIR/rootwrap.conf
IRONIC_INSPECTOR_ADMIN_USER=${IRONIC_INSPECTOR_ADMIN_USER:-ironic-inspector}
IRONIC_INSPECTOR_AUTH_CACHE_DIR=${IRONIC_INSPECTOR_AUTH_CACHE_DIR:-/var/cache/ironic-inspector}
IRONIC_INSPECTOR_MANAGE_FIREWALL=$(trueorfalse True IRONIC_INSPECTOR_MANAGE_FIREWALL)
IRONIC_INSPECTOR_HOST=$HOST_IP
IRONIC_INSPECTOR_PORT=5050
IRONIC_INSPECTOR_URI="http://$IRONIC_INSPECTOR_HOST:$IRONIC_INSPECTOR_PORT"
IRONIC_INSPECTOR_BUILD_RAMDISK=$(trueorfalse False IRONIC_INSPECTOR_BUILD_RAMDISK)
IRONIC_AGENT_KERNEL_URL=${IRONIC_AGENT_KERNEL_URL:-http://tarballs.openstack.org/ironic-python-agent/coreos/files/coreos_production_pxe.vmlinuz}
IRONIC_AGENT_RAMDISK_URL=${IRONIC_AGENT_RAMDISK_URL:-http://tarballs.openstack.org/ironic-python-agent/coreos/files/coreos_production_pxe_image-oem.cpio.gz}
IRONIC_INSPECTOR_RAMDISK_ELEMENT=${IRONIC_INSPECTOR_RAMDISK_ELEMENT:-ironic-discoverd-ramdisk}
IRONIC_INSPECTOR_RAMDISK_FLAVOR=${IRONIC_INSPECTOR_RAMDISK_FLAVOR:-fedora $IRONIC_INSPECTOR_RAMDISK_ELEMENT}
IRONIC_INSPECTOR_COLLECTORS=${IRONIC_INSPECTOR_COLLECTORS:-default,logs}
IRONIC_INSPECTOR_RAMDISK_LOGDIR=${IRONIC_INSPECTOR_RAMDISK_LOGDIR:-$IRONIC_INSPECTOR_DATA_DIR/ramdisk-logs}
IRONIC_INSPECTOR_ALWAYS_STORE_RAMDISK_LOGS=${IRONIC_INSPECTOR_ALWAYS_STORE_RAMDISK_LOGS:-True}
# These should not overlap with other ranges/networks
IRONIC_INSPECTOR_INTERNAL_IP=${IRONIC_INSPECTOR_INTERNAL_IP:-172.24.42.254}
IRONIC_INSPECTOR_INTERNAL_SUBNET_SIZE=${IRONIC_INSPECTOR_INTERNAL_SUBNET_SIZE:-24}
IRONIC_INSPECTOR_DHCP_RANGE=${IRONIC_INSPECTOR_DHCP_RANGE:-172.24.42.100,172.24.42.253}
IRONIC_INSPECTOR_INTERFACE=${IRONIC_INSPECTOR_INTERFACE:-br-inspector}
IRONIC_INSPECTOR_INTERNAL_URI="http://$IRONIC_INSPECTOR_INTERNAL_IP:$IRONIC_INSPECTOR_PORT"
IRONIC_INSPECTOR_INTERNAL_IP_WITH_NET=$IRONIC_INSPECTOR_INTERNAL_IP/$IRONIC_INSPECTOR_INTERNAL_SUBNET_SIZE

GITDIR["python-ironic-inspector-client"]=$DEST/python-ironic-inspector-client
GITREPO["python-ironic-inspector-client"]=${IRONIC_INSPECTOR_CLIENT_REPO:-${GIT_BASE}/openstack/python-ironic-inspector-client.git}
GITBRANCH["python-ironic-inspector-client"]=${IRONIC_INSPECTOR_CLIENT_BRANCH:-master}

### Utilities

function mkdir_chown_stack {
    if [[ ! -d "$1" ]]; then
        sudo mkdir -p "$1"
    fi
    sudo chown $STACK_USER "$1"
}

function inspector_iniset {
    iniset "$IRONIC_INSPECTOR_CONF_FILE" $1 $2 $3
}

### Install-start-stop

function install_inspector {
    setup_develop $IRONIC_INSPECTOR_DIR
    # NOTE(dtantsur): required for tests
    install_package jq
}

function install_inspector_dhcp {
    install_package dnsmasq
}

function install_inspector_client {
    if use_library_from_git python-ironic-inspector-client; then
        git_clone_by_name python-ironic-inspector-client
        setup_dev_lib python-ironic-inspector-client
    else
        # TODO(dtantsur): switch to pip_install_gr
        pip_install python-ironic-inspector-client
    fi
}

function start_inspector {
    screen_it ironic-inspector \
        "cd $IRONIC_INSPECTOR_DIR && $IRONIC_INSPECTOR_CMD"
}

function start_inspector_dhcp {
    screen_it ironic-inspector-dhcp \
        "sudo dnsmasq --conf-file=$IRONIC_INSPECTOR_DHCP_CONF_FILE"
}

function stop_inspector {
    screen -S $SCREEN_NAME -p ironic-inspector -X kill
}

function stop_inspector_dhcp {
    screen -S $SCREEN_NAME -p ironic-inspector-dhcp -X kill
}

function inspector_uses_ipa {
    [[ $IRONIC_INSPECTOR_RAMDISK_ELEMENT = "ironic-agent" ]] || [[ $IRONIC_INSPECTOR_RAMDISK_FLAVOR =~ (ironic-agent$|^ironic-agent) ]] && return 0
    return 1
}

### Configuration

function prepare_tftp {
    IRONIC_INSPECTOR_IMAGE_PATH="$TOP_DIR/files/ironic-inspector"
    IRONIC_INSPECTOR_INITRAMFS_PATH="$IRONIC_INSPECTOR_IMAGE_PATH.initramfs"
    IRONIC_INSPECTOR_CALLBACK_URI="$IRONIC_INSPECTOR_INTERNAL_URI/v1/continue"

    if  inspector_uses_ipa; then
        IRONIC_INSPECTOR_KERNEL_CMDLINE="ipa-inspection-callback-url=$IRONIC_INSPECTOR_CALLBACK_URI systemd.journald.forward_to_console=yes"
        IRONIC_INSPECTOR_KERNEL_CMDLINE="$IRONIC_INSPECTOR_KERNEL_CMDLINE ipa-inspection-collectors=$IRONIC_INSPECTOR_COLLECTORS"
        if [[ "$IRONIC_INSPECTOR_BUILD_RAMDISK" == "True" ]]; then
            IRONIC_INSPECTOR_KERNEL_PATH="$IRONIC_INSPECTOR_IMAGE_PATH.vmlinuz"
            if [ ! -e "$IRONIC_INSPECTOR_KERNEL_PATH" -o ! -e "$IRONIC_INSPECTOR_INITRAMFS_PATH" ]; then
                if [[ $(type -P disk-image-create) == "" ]]; then
                    pip_install_gr diskimage-builder
                fi
                disk-image-create $IRONIC_INSPECTOR_RAMDISK_FLAVOR \
                    -o $IRONIC_INSPECTOR_IMAGE_PATH
                sudo chown $STACK_USER $IRONIC_INSPECTOR_KERNEL_PATH
            fi
        else
            # download the agent image tarball
            IRONIC_INSPECTOR_KERNEL_PATH="$IRONIC_INSPECTOR_IMAGE_PATH.kernel"
            wget "$IRONIC_AGENT_KERNEL_URL" -O $IRONIC_INSPECTOR_KERNEL_PATH
            wget "$IRONIC_AGENT_RAMDISK_URL" -O $IRONIC_INSPECTOR_INITRAMFS_PATH
        fi
    else
        IRONIC_INSPECTOR_KERNEL_PATH="$IRONIC_INSPECTOR_IMAGE_PATH.kernel"
        IRONIC_INSPECTOR_KERNEL_CMDLINE="discoverd_callback_url=$IRONIC_INSPECTOR_CALLBACK_URI inspector_callback_url=$IRONIC_INSPECTOR_CALLBACK_URI"
        if [ ! -e "$IRONIC_INSPECTOR_KERNEL_PATH" -o ! -e "$IRONIC_INSPECTOR_INITRAMFS_PATH" ]; then
            if [[ $(type -P ramdisk-image-create) == "" ]]; then
                pip_install diskimage_builder
            fi
            ramdisk-image-create $IRONIC_INSPECTOR_RAMDISK_FLAVOR \
                -o $IRONIC_INSPECTOR_IMAGE_PATH
        fi
    fi

    mkdir_chown_stack "$IRONIC_TFTPBOOT_DIR/pxelinux.cfg"
    cp $IRONIC_INSPECTOR_KERNEL_PATH $IRONIC_TFTPBOOT_DIR/ironic-inspector.kernel
    cp $IRONIC_INSPECTOR_INITRAMFS_PATH $IRONIC_TFTPBOOT_DIR

    cat > "$IRONIC_TFTPBOOT_DIR/pxelinux.cfg/default" <<EOF
default inspect

label inspect
kernel ironic-inspector.kernel
append initrd=ironic-inspector.initramfs $IRONIC_INSPECTOR_KERNEL_CMDLINE

ipappend 3
EOF
}

function configure_inspector {
    mkdir_chown_stack "$IRONIC_INSPECTOR_CONF_DIR"
    mkdir_chown_stack "$IRONIC_INSPECTOR_DATA_DIR"

    create_service_user "$IRONIC_INSPECTOR_ADMIN_USER" "admin"

    cp "$IRONIC_INSPECTOR_DIR/example.conf" "$IRONIC_INSPECTOR_CONF_FILE"
    inspector_iniset DEFAULT debug $IRONIC_INSPECTOR_DEBUG
    inspector_iniset ironic os_auth_url "$KEYSTONE_SERVICE_URI/v2.0"
    inspector_iniset ironic os_username $IRONIC_INSPECTOR_ADMIN_USER
    inspector_iniset ironic os_password $SERVICE_PASSWORD
    inspector_iniset ironic os_tenant_name $SERVICE_TENANT_NAME

    configure_auth_token_middleware $IRONIC_INSPECTOR_CONF_FILE $IRONIC_INSPECTOR_ADMIN_USER $IRONIC_INSPECTOR_AUTH_CACHE_DIR/api

    inspector_iniset DEFAULT listen_port $IRONIC_INSPECTOR_PORT
    inspector_iniset DEFAULT listen_address 0.0.0.0  # do not change

    inspector_iniset firewall manage_firewall $IRONIC_INSPECTOR_MANAGE_FIREWALL
    inspector_iniset firewall dnsmasq_interface $IRONIC_INSPECTOR_INTERFACE
    inspector_iniset database connection `database_connection_url ironic_inspector`

    is_service_enabled swift && configure_inspector_swift

    iniset "$IRONIC_CONF_FILE" inspector enabled True
    iniset "$IRONIC_CONF_FILE" inspector service_url $IRONIC_INSPECTOR_URI

    if [ "$LOG_COLOR" == "True" ] && [ "$SYSLOG" == "False" ]; then
        setup_colorized_logging $IRONIC_INSPECTOR_CONF_FILE DEFAULT
    fi

    cp "$IRONIC_INSPECTOR_DIR/rootwrap.conf" "$IRONIC_INSPECTOR_ROOTWRAP_CONF_FILE"
    cp -r "$IRONIC_INSPECTOR_DIR/rootwrap.d" "$IRONIC_INSPECTOR_CONF_DIR"
    local ironic_inspector_rootwrap=$(get_rootwrap_location ironic-inspector)
    local rootwrap_sudoer_cmd="$ironic_inspector_rootwrap $IRONIC_INSPECTOR_CONF_DIR/rootwrap.conf *"

    # Set up the rootwrap sudoers for ironic-inspector
    local tempfile=`mktemp`
    echo "$STACK_USER ALL=(root) NOPASSWD: $rootwrap_sudoer_cmd" >$tempfile
    chmod 0640 $tempfile
    sudo chown root:root $tempfile
    sudo mv $tempfile /etc/sudoers.d/ironic-inspector-rootwrap

    inspector_iniset DEFAULT rootwrap_config $IRONIC_INSPECTOR_ROOTWRAP_CONF_FILE

    mkdir_chown_stack "$IRONIC_INSPECTOR_RAMDISK_LOGDIR"
    inspector_iniset processing ramdisk_logs_dir "$IRONIC_INSPECTOR_RAMDISK_LOGDIR"
    inspector_iniset processing always_store_ramdisk_logs "$IRONIC_INSPECTOR_ALWAYS_STORE_RAMDISK_LOGS"
    inspector_iniset processing log_bmc_address False
}

function configure_inspector_swift {
    inspector_iniset swift os_auth_url "$KEYSTONE_SERVICE_URI/v2.0"
    inspector_iniset swift username $IRONIC_INSPECTOR_ADMIN_USER
    inspector_iniset swift password $SERVICE_PASSWORD
    inspector_iniset swift tenant_name $SERVICE_TENANT_NAME

    inspector_iniset processing store_data swift
}

function configure_inspector_dhcp {
    mkdir_chown_stack "$IRONIC_INSPECTOR_CONF_DIR"

    cat > "$IRONIC_INSPECTOR_DHCP_CONF_FILE" <<EOF
no-daemon
port=0
interface=$IRONIC_INSPECTOR_INTERFACE
bind-interfaces
dhcp-range=$IRONIC_INSPECTOR_DHCP_RANGE
dhcp-boot=pxelinux.0
EOF
}

function prepare_environment {
    prepare_tftp
    create_ironic_inspector_cache_dir

    sudo ip link add brbm-inspector type veth peer name $IRONIC_INSPECTOR_INTERFACE
    sudo ip link set dev brbm-inspector up
    sudo ip link set dev $IRONIC_INSPECTOR_INTERFACE up
    sudo ovs-vsctl add-port brbm brbm-inspector
    sudo ip addr add $IRONIC_INSPECTOR_INTERNAL_IP_WITH_NET dev $IRONIC_INSPECTOR_INTERFACE

    sudo iptables -I INPUT -i $IRONIC_INSPECTOR_INTERFACE -p udp \
        --dport 69 -j ACCEPT
    sudo iptables -I INPUT -i $IRONIC_INSPECTOR_INTERFACE -p tcp \
        --dport $IRONIC_INSPECTOR_PORT -j ACCEPT
}

# create_ironic_inspector_cache_dir() - Part of the prepare_environment() process
function create_ironic_inspector_cache_dir {
    # Create cache dir
    mkdir_chown_stack $IRONIC_INSPECTOR_AUTH_CACHE_DIR/api
    rm -f $IRONIC_INSPECTOR_AUTH_CACHE_DIR/api/*
    mkdir_chown_stack $IRONIC_INSPECTOR_AUTH_CACHE_DIR/registry
    rm -f $IRONIC_INSPECTOR_AUTH_CACHE_DIR/registry/*
}

function cleanup_inspector {
    rm -f $IRONIC_TFTPBOOT_DIR/pxelinux.cfg/default
    rm -f $IRONIC_TFTPBOOT_DIR/ironic-inspector.*
    sudo rm -f /etc/sudoers.d/ironic-inspector-rootwrap
    sudo rm -rf $IRONIC_INSPECTOR_AUTH_CACHE_DIR
    sudo rm -rf "$IRONIC_INSPECTOR_RAMDISK_LOGDIR"

    # Try to clean up firewall rules
    sudo iptables -D INPUT -i $IRONIC_INSPECTOR_INTERFACE -p udp \
        --dport 69 -j ACCEPT | true
    sudo iptables -D INPUT -i $IRONIC_INSPECTOR_INTERFACE -p tcp \
        --dport $IRONIC_INSPECTOR_PORT -j ACCEPT | true
    sudo iptables -D INPUT -i $IRONIC_INSPECTOR_INTERFACE -p udp \
        --dport 67 -j ironic-inspector | true
    sudo iptables -F ironic-inspector | true
    sudo iptables -X ironic-inspector | true

    sudo ip link show $IRONIC_INSPECTOR_INTERFACE && sudo ip link delete $IRONIC_INSPECTOR_INTERFACE
    sudo ip link show brbm-inspector && sudo ip link delete brbm-inspector
    sudo ovs-vsctl --if-exists del-port brbm-inspector
}

function sync_inspector_database {
    recreate_database ironic_inspector
    $IRONIC_INSPECTOR_DBSYNC_BIN_FILE --config-file $IRONIC_INSPECTOR_CONF_FILE upgrade
}

### Entry points

if [[ "$1" == "stack" && "$2" == "install" ]]; then
    echo_summary "Installing ironic-inspector"
    if [[ "$IRONIC_INSPECTOR_MANAGE_FIREWALL" == "True" ]]; then
        install_inspector_dhcp
    fi
    install_inspector
    install_inspector_client
elif [[ "$1" == "stack" && "$2" == "post-config" ]]; then
    echo_summary "Configuring ironic-inspector"
    cleanup_inspector
    if [[ "$IRONIC_INSPECTOR_MANAGE_FIREWALL" == "True" ]]; then
        configure_inspector_dhcp
    fi
    configure_inspector
    sync_inspector_database
elif [[ "$1" == "stack" && "$2" == "extra" ]]; then
    echo_summary "Initializing ironic-inspector"
    prepare_environment
    if [[ "$IRONIC_INSPECTOR_MANAGE_FIREWALL" == "True" ]]; then
        start_inspector_dhcp
    fi
    start_inspector
fi

if [[ "$1" == "unstack" ]]; then
    stop_inspector
    if [[ "$IRONIC_INSPECTOR_MANAGE_FIREWALL" == "True" ]]; then
        stop_inspector_dhcp
    fi
    cleanup_inspector
fi
