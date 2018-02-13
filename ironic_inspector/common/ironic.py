# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import socket

from ironicclient import client
from ironicclient import exceptions as ironic_exc
import netaddr
from oslo_config import cfg
import retrying

from ironic_inspector.common.i18n import _
from ironic_inspector.common import keystone
from ironic_inspector import utils

CONF = cfg.CONF
LOG = utils.getProcessingLogger(__name__)

# See http://specs.openstack.org/openstack/ironic-specs/specs/kilo/new-ironic-state-machine.html  # noqa
VALID_STATES = {'enroll', 'manageable', 'inspecting', 'inspect failed'}

# 1.19 is API version, which supports port.pxe_enabled
DEFAULT_IRONIC_API_VERSION = '1.19'

IRONIC_SESSION = None


class NotFound(utils.Error):
    """Node not found in Ironic."""

    def __init__(self, node_ident, code=404, *args, **kwargs):
        msg = _('Node %s was not found in Ironic') % node_ident
        super(NotFound, self).__init__(msg, code, *args, **kwargs)


def reset_ironic_session():
    """Reset the global session variable.

    Mostly useful for unit tests.
    """
    global IRONIC_SESSION
    IRONIC_SESSION = None


def get_ipmi_address(node):
    ipmi_fields = ['ipmi_address'] + CONF.ipmi_address_fields
    # NOTE(sambetts): IPMI Address is useless to us if bridging is enabled so
    # just ignore it and return None
    if node.driver_info.get("ipmi_bridging", "no") != "no":
        return
    for name in ipmi_fields:
        value = node.driver_info.get(name)
        if not value:
            continue

        try:
            ip = socket.gethostbyname(value)
        except socket.gaierror:
            msg = _('Failed to resolve the hostname (%(value)s)'
                    ' for node %(uuid)s')
            raise utils.Error(msg % {'value': value,
                                     'uuid': node.uuid},
                              node_info=node)

        if netaddr.IPAddress(ip).is_loopback():
            LOG.warning('Ignoring loopback BMC address %s', ip,
                        node_info=node)
            ip = None

        return ip


def get_client(token=None,
               api_version=DEFAULT_IRONIC_API_VERSION):  # pragma: no cover
    """Get Ironic client instance."""
    global IRONIC_SESSION

    # NOTE: To support standalone ironic without keystone
    # TODO(pas-ha) remove handling of deprecated opts in Rocky
    # TODO(pas-ha) rewrite when ironicclient natively supports 'none' auth
    # via sessions https://review.openstack.org/#/c/359061/
    if CONF.ironic.auth_strategy == 'noauth':
        CONF.set_override('auth_type', 'none', group='ironic')

    if not IRONIC_SESSION:
        IRONIC_SESSION = keystone.get_session('ironic')

    args = {
        'os_ironic_api_version': api_version,
        'max_retries': CONF.ironic.max_retries,
        'retry_interval': CONF.ironic.retry_interval}

    adapter_opts = dict()

    # TODO(pas-ha) use service auth with incoming token
    if CONF.ironic.auth_type != 'none':
        if token is None:
            args['session'] = IRONIC_SESSION
        else:
            args['token'] = token

    # TODO(pas-ha): remove handling of deprecated options in Rocky
    if CONF.ironic.os_region and not CONF.ironic.region_name:
        adapter_opts['region_name'] = CONF.ironic.os_region
    if (CONF.ironic.auth_type == 'none' and
            not CONF.ironic.endpoint_override and
            CONF.ironic.ironic_url):
        adapter_opts['endpoint_override'] = CONF.ironic.ironic_url

    adapter = keystone.get_adapter('ironic', session=IRONIC_SESSION,
                                   **adapter_opts)
    endpoint = adapter.get_endpoint()
    return client.Client(1, endpoint, **args)


def check_provision_state(node):
    state = node.provision_state.lower()
    if state not in VALID_STATES:
        msg = _('Invalid provision state for introspection: '
                '"%(state)s", valid states are "%(valid)s"')
        raise utils.Error(msg % {'state': state, 'valid': list(VALID_STATES)},
                          node_info=node)


def capabilities_to_dict(caps):
    """Convert the Node's capabilities into a dictionary."""
    if not caps:
        return {}
    return dict([key.split(':', 1) for key in caps.split(',')])


def dict_to_capabilities(caps_dict):
    """Convert a dictionary into a string with the capabilities syntax."""
    return ','.join(["%s:%s" % (key, value)
                     for key, value in caps_dict.items()
                     if value is not None])


def get_node(node_id, ironic=None, **kwargs):
    """Get a node from Ironic.

    :param node_id: node UUID or name.
    :param ironic: ironic client instance.
    :param kwargs: arguments to pass to Ironic client.
    :raises: Error on failure
    """
    ironic = ironic if ironic is not None else get_client()

    try:
        return ironic.node.get(node_id, **kwargs)
    except ironic_exc.NotFound:
        raise NotFound(node_id)
    except ironic_exc.HttpError as exc:
        raise utils.Error(_("Cannot get node %(node)s: %(exc)s") %
                          {'node': node_id, 'exc': exc})


@retrying.retry(
    retry_on_exception=lambda exc: isinstance(exc, ironic_exc.ClientException),
    stop_max_attempt_number=5, wait_fixed=1000)
def call_with_retries(func, *args, **kwargs):
    """Call an ironic client function retrying all errors.

    If an ironic client exception is raised, try calling the func again,
    at most 5 times, waiting 1 sec between each call. If on the 5th attempt
    the func raises again, the exception is propagated to the caller.
    """
    return func(*args, **kwargs)
