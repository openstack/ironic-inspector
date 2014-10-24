from six.moves import configparser


DEFAULTS = {
    'debug': 'false',
    'listen_address': '0.0.0.0',
    'listen_port': '5050',
    'dnsmasq_interface': 'br-ctlplane',
    'authenticate': 'true',
    'firewall_update_period': '15',
    'ports_for_inactive_interfaces': 'false',
    'ironic_retry_attempts': '5',
    'ironic_retry_period': '5'
}


def init_conf():
    global CONF, get, getint, getboolean, read
    CONF = configparser.ConfigParser(defaults=DEFAULTS)
    get = CONF.get
    getint = CONF.getint
    getboolean = CONF.getboolean
    read = CONF.read


init_conf()
