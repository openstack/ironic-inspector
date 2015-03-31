IRONIC_DISCOVERD_DEBUG=${IRONIC_DISCOVERD_DEBUG:-false}
IRONIC_DISCOVERD_DIR=$DEST/ironic-discoverd
IRONIC_DISCOVERD_BIN_DIR=$(get_python_exec_prefix)
IRONIC_DISCOVERD_BIN_FILE=$IRONIC_DISCOVERD_BIN_DIR/ironic-discoverd
IRONIC_DISCOVERD_CONF_DIR=${IRONIC_DISCOVERD_CONF_DIR:-/etc/ironic-discoverd}
IRONIC_DISCOVERD_CONF_FILE=$IRONIC_DISCOVERD_CONF_DIR/discoverd.conf
IRONIC_DISCOVERD_DHCP_CONF_FILE=$IRONIC_DISCOVERD_CONF_DIR/dnsmasq.conf
IRONIC_DISCOVERD_DATA_DIR=$DATA_DIR/ironic-discoverd
IRONIC_DISCOVERD_ADMIN_USER=${IRONIC_DISCOVERD_ADMIN_USER:-ironic-discoverd}
IRONIC_DISCOVERD_MANAGE_FIREWALL=$(trueorfalse True $IRONIC_DISCOVERD_MANAGE_FIREWALL)
IRONIC_DISCOVERD_HOST=$HOST_IP
IRONIC_DISCOVERD_PORT=5050
IRONIC_DISCOVERD_URI="http://$IRONIC_DISCOVERD_HOST:$IRONIC_DISCOVERD_PORT"
IRONIC_DISCOVERD_RAMDISK_ELEMENT=${IRONIC_DISCOVERD_RAMDISK_ELEMENT:-ironic-discoverd-ramdisk}
IRONIC_DISCOVERD_RAMDISK_FLAVOR=${IRONIC_DISCOVERD_RAMDISK_FLAVOR:-fedora $IRONIC_DISCOVERD_RAMDISK_ELEMENT}
# These should not overlap with other ranges/networks
IRONIC_DISCOVERD_INTERNAL_IP=${IRONIC_DISCOVERD_INTERNAL_IP:-172.24.5.254}
IRONIC_DISCOVERD_INTERNAL_SUBNET_SIZE=${IRONIC_DISCOVERD_INTERNAL_SUBNET_SIZE:-24}
IRONIC_DISCOVERD_DHCP_RANGE=${IRONIC_DISCOVERD_DHCP_RANGE:-172.24.5.100,172.24.5.253}
IRONIC_DISCOVERD_INTERFACE=${IRONIC_DISCOVERD_INTERFACE:-br-discoverd}
IRONIC_DISCOVERD_INTERNAL_URI="http://$IRONIC_DISCOVERD_INTERNAL_IP:$IRONIC_DISCOVERD_PORT"
IRONIC_DISCOVERD_INTERNAL_IP_WITH_NET=$IRONIC_DISCOVERD_INTERNAL_IP/$IRONIC_DISCOVERD_INTERNAL_SUBNET_SIZE

### Utilities

function mkdir_chown_stack {
    if [[ ! -d "$1" ]]; then
        sudo mkdir -p "$1"
    fi
    sudo chown $STACK_USER "$1"
}

function discoverd_iniset {
    iniset "$IRONIC_DISCOVERD_CONF_FILE" discoverd $1 $2
}

### Install-start-stop

function install_discoverd {
    setup_develop $IRONIC_DISCOVERD_DIR
}

function install_discoverd_dhcp {
    install_package dnsmasq
}

function start_discoverd {
    screen_it ironic-discoverd "cd $IRONIC_DISCOVERD_DIR && sudo $IRONIC_DISCOVERD_BIN_FILE --config-file $IRONIC_DISCOVERD_CONF_FILE"
}

function start_discoverd_dhcp {
    screen_it ironic-discoverd-dhcp "sudo dnsmasq --conf-file=$IRONIC_DISCOVERD_DHCP_CONF_FILE"
}

function stop_discoverd {
    screen -S $SCREEN_NAME -p ironic-discoverd -X kill
}

function stop_discoverd_dhcp {
    screen -S $SCREEN_NAME -p ironic-discoverd-dhcp -X kill
}

### Configuration

function prepare_tftp {
    IRONIC_DISCOVERD_IMAGE_PATH="$TOP_DIR/files/ironic-discoverd"
    IRONIC_DISCOVERD_KERNEL_PATH="$IRONIC_DISCOVERD_IMAGE_PATH.kernel"
    IRONIC_DISCOVERD_INITRAMFS_PATH="$IRONIC_DISCOVERD_IMAGE_PATH.initramfs"

    if [ ! -e "$IRONIC_DISCOVERD_KERNEL_PATH" -o ! -e "$IRONIC_DISCOVERD_INITRAMFS_PATH" ]; then
        if [[ $(type -P ramdisk-image-create) == "" ]]; then
            pip_install diskimage_builder
        fi
        ramdisk-image-create $IRONIC_DISCOVERD_RAMDISK_FLAVOR \
            -o $IRONIC_DISCOVERD_IMAGE_PATH
    fi

    mkdir_chown_stack "$IRONIC_TFTPBOOT_DIR/pxelinux.cfg"

    cp $IRONIC_DISCOVERD_KERNEL_PATH $IRONIC_DISCOVERD_INITRAMFS_PATH \
        $IRONIC_TFTPBOOT_DIR
    cat > "$IRONIC_TFTPBOOT_DIR/pxelinux.cfg/default" <<EOF
default discover

label discover
kernel ironic-discoverd.kernel
append initrd=ironic-discoverd.initramfs discoverd_callback_url=$IRONIC_DISCOVERD_INTERNAL_URI/v1/continue

ipappend 3
EOF
}

function configure_discoverd {
    mkdir_chown_stack "$IRONIC_DISCOVERD_CONF_DIR"
    mkdir_chown_stack "$IRONIC_DISCOVERD_DATA_DIR"

    create_service_user "$IRONIC_DISCOVERD_ADMIN_USER" "admin"

    cp "$IRONIC_DISCOVERD_DIR/example.conf" "$IRONIC_DISCOVERD_CONF_FILE"
    discoverd_iniset debug $IRONIC_DISCOVERD_DEBUG
    discoverd_iniset identity_uri "$KEYSTONE_AUTH_URI"
    discoverd_iniset os_auth_url "$KEYSTONE_SERVICE_URI/v2.0"
    discoverd_iniset os_username $IRONIC_DISCOVERD_ADMIN_USER
    discoverd_iniset os_password $SERVICE_PASSWORD
    discoverd_iniset os_tenant_name $SERVICE_TENANT_NAME

    discoverd_iniset listen_port $IRONIC_DISCOVERD_PORT
    discoverd_iniset listen_address 0.0.0.0  # do not change

    discoverd_iniset manage_firewall $IRONIC_DISCOVERD_MANAGE_FIREWALL
    discoverd_iniset dnsmasq_interface $IRONIC_DISCOVERD_INTERFACE
    discoverd_iniset database $IRONIC_DISCOVERD_DATA_DIR/discoverd.sqlite

    iniset "$IRONIC_CONF_FILE" discoverd enabled True
    iniset "$IRONIC_CONF_FILE" discoverd service_url $IRONIC_DISCOVERD_URI
}

function configure_discoverd_dhcp {
    mkdir_chown_stack "$IRONIC_DISCOVERD_CONF_DIR"

    cat > "$IRONIC_DISCOVERD_DHCP_CONF_FILE" <<EOF
no-daemon
port=0
interface=$IRONIC_DISCOVERD_INTERFACE
bind-interfaces
dhcp-range=$IRONIC_DISCOVERD_DHCP_RANGE
dhcp-boot=pxelinux.0
EOF
}

function prepare_environment {
    prepare_tftp

    sudo ip link add brbm-discoverd type veth peer name $IRONIC_DISCOVERD_INTERFACE
    sudo ip link set dev brbm-discoverd up
    sudo ip link set dev $IRONIC_DISCOVERD_INTERFACE up
    sudo ovs-vsctl add-port brbm brbm-discoverd
    sudo ip addr add $IRONIC_DISCOVERD_INTERNAL_IP_WITH_NET dev $IRONIC_DISCOVERD_INTERFACE

    sudo iptables -I INPUT -i $IRONIC_DISCOVERD_INTERFACE -p udp \
        --dport 69 -j ACCEPT
    sudo iptables -I INPUT -i $IRONIC_DISCOVERD_INTERFACE -p tcp \
        --dport $IRONIC_DISCOVERD_PORT -j ACCEPT
}

function cleanup_discoverd {
    rm -rf $IRONIC_DISCOVERD_DATA_DIR
    rm -f $IRONIC_TFTPBOOT_DIR/pxelinux.cfg/default
    rm -f $IRONIC_TFTPBOOT_DIR/ironic-discoverd.*

    # Try to clean up firewall rules
    sudo iptables -D INPUT -i $IRONIC_DISCOVERD_INTERFACE -p udp \
        --dport 69 -j ACCEPT | true
    sudo iptables -D INPUT -i $IRONIC_DISCOVERD_INTERFACE -p tcp \
        --dport $IRONIC_DISCOVERD_PORT -j ACCEPT | true
    sudo iptables -D INPUT -i $IRONIC_DISCOVERD_INTERFACE -p udp \
        --dport 67 -j discovery | true
    sudo iptables -F discovery | true
    sudo iptables -X discovery | true

    sudo ip link show $IRONIC_DISCOVERD_INTERFACE && sudo ip link delete $IRONIC_DISCOVERD_INTERFACE
    sudo ip link show brbm-discoverd && sudo ip link delete brbm-discoverd
    sudo ovs-vsctl --if-exists del-port brbm-discoverd
}

### Entry points

if [[ "$1" == "stack" && "$2" == "install" ]]; then
    echo_summary "Installing ironic-discoverd"
    if [[ "$IRONIC_DISCOVERD_MANAGE_FIREWALL" == "True" ]]; then
        install_discoverd_dhcp
    fi
    install_discoverd
elif [[ "$1" == "stack" && "$2" == "post-config" ]]; then
    echo_summary "Configuring ironic-discoverd"
    cleanup_discoverd
    if [[ "$IRONIC_DISCOVERD_MANAGE_FIREWALL" == "True" ]]; then
        configure_discoverd_dhcp
    fi
    configure_discoverd
elif [[ "$1" == "stack" && "$2" == "extra" ]]; then
    echo_summary "Initializing ironic-discoverd"
    prepare_environment
    if [[ "$IRONIC_DISCOVERD_MANAGE_FIREWALL" == "True" ]]; then
        start_discoverd_dhcp
    fi
    start_discoverd
fi

if [[ "$1" == "unstack" ]]; then
    stop_discoverd
    if [[ "$IRONIC_DISCOVERD_MANAGE_FIREWALL" == "True" ]]; then
        stop_discoverd_dhcp
    fi
    cleanup_discoverd
fi
