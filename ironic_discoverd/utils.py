import logging
import re

import eventlet
from ironicclient import client
from keystoneclient.v2_0 import client as keystone
import six

from ironic_discoverd import conf


LOG = logging.getLogger('discoverd')
OS_ARGS = ('os_password', 'os_username', 'os_auth_url', 'os_tenant_name')


def get_client():  # pragma: no cover
    args = dict((k, conf.get('discoverd', k)) for k in OS_ARGS)
    return client.get_client(1, **args)


def get_keystone(token):  # pragma: no cover
    return keystone.Client(token=token, auth_url=conf.get('discoverd',
                                                          'os_auth_url'))


def is_valid_mac(address):
    m = "[0-9a-f]{2}(:[0-9a-f]{2}){5}$"
    return (isinstance(address, six.string_types)
            and re.match(m, address.lower()))


def check_ironic_available():
    """Try to make sure:
    1. Keystone access is configured properly
    2. Keystone has already started
    3. Ironic has already started
    """
    attempts = conf.getint('discoverd', 'ironic_retry_attempts')
    assert attempts >= 0
    retry_period = conf.getint('discoverd', 'ironic_retry_period')
    LOG.info('Trying to connect to Ironic')
    for i in range(attempts + 1):  # one attempt always required
        try:
            get_client().driver.list()
        except Exception as exc:
            if i == attempts:
                raise
            LOG.error('Unable to connect to Ironic or Keystone, retrying %d '
                      'times more: %s', attempts - i, exc)
        else:
            break
        eventlet.greenthread.sleep(retry_period)
