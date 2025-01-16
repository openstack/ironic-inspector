#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

"""Multicast DNS implementation for API discovery.

This implementation follows RFC 6763 as clarified by the API SIG guideline
https://review.opendev.org/651222.
"""

import collections
import ipaddress
import logging
import socket
import time
from urllib import parse as urlparse

from oslo_config import cfg
import zeroconf

from ironic_inspector.common import exception
from ironic_inspector.common.i18n import _
from ironic_inspector import utils

LOG = logging.getLogger(__name__)

_MDNS_DOMAIN = '_openstack._tcp.local.'
_endpoint = collections.namedtuple('Endpoint',
                                   ['addresses', 'hostname', 'port', 'params'])


CONF = cfg.CONF


class Zeroconf(object):
    """Multicast DNS implementation client and server.

    Uses threading internally, so there is no start method. It starts
    automatically on creation.

    .. warning::
        The underlying library does not yet support IPv6.
    """

    def __init__(self):
        """Initialize and start the mDNS server."""
        interfaces = (CONF.mdns.interfaces if CONF.mdns.interfaces
                      else zeroconf.InterfaceChoice.All)
        # If interfaces are set, let zeroconf auto-detect the version
        ip_version = None if CONF.mdns.interfaces else zeroconf.IPVersion.All
        self._zc = zeroconf.Zeroconf(interfaces=interfaces,
                                     ip_version=ip_version)
        self._registered = []

    def register_service(self, service_type, endpoint, params=None):
        """Register a service.

        This call announces the new services via multicast and instructs the
        built-in server to respond to queries about it.

        :param service_type: OpenStack service type, e.g. "baremetal".
        :param endpoint: full endpoint to reach the service.
        :param params: optional properties as a dictionary.
        :raises: :exc:`.ServiceRegistrationFailure` if the service cannot be
            registered, e.g. because of conflicts.
        """
        parsed = _parse_endpoint(endpoint, service_type)

        all_params = CONF.mdns.params.copy()
        if params:
            all_params.update(params)
        all_params.update(parsed.params)

        properties = {
            (key.encode('utf-8') if isinstance(key, str) else key):
            (value.encode('utf-8') if isinstance(value, str) else value)
            for key, value in all_params.items()
        }

        # TODO(dtantsur): allow overriding TTL values via configuration
        info = zeroconf.ServiceInfo(_MDNS_DOMAIN,
                                    '%s.%s' % (service_type, _MDNS_DOMAIN),
                                    addresses=parsed.addresses,
                                    port=parsed.port,
                                    properties=properties,
                                    server=parsed.hostname)

        LOG.debug('Registering %s via mDNS', info)
        # Work around a potential race condition in the registration code:
        # https://github.com/jstasiak/python-zeroconf/issues/163
        delay = 0.1
        try:
            for attempt in range(CONF.mdns.registration_attempts):
                try:
                    self._zc.register_service(info)
                except zeroconf.NonUniqueNameException:
                    LOG.debug('Could not register %s - conflict', info)
                    if attempt == CONF.mdns.registration_attempts - 1:
                        raise
                    # reset the cache to purge learned records and retry
                    self._zc.cache = zeroconf.DNSCache()
                    time.sleep(delay)
                    delay *= 2
                else:
                    break
        except zeroconf.Error as exc:
            raise exception.ServiceRegistrationFailure(
                service=service_type, error=exc)

        self._registered.append(info)

    def get_endpoint(self, service_type, skip_loopback=True,  # noqa: C901
                     skip_link_local=False):
        """Get an endpoint and its properties from mDNS.

        If the requested endpoint is already in the built-in server cache, and
        its TTL is not exceeded, the cached value is returned.

        :param service_type: OpenStack service type.
        :param skip_loopback: Whether to ignore loopback addresses.
        :param skip_link_local: Whether to ignore link local V6 addresses.
        :returns: tuple (endpoint URL, properties as a dict).
        :raises: :exc:`.ServiceLookupFailure` if the service cannot be found.
        """
        delay = 0.1
        for attempt in range(CONF.mdns.lookup_attempts):
            name = '%s.%s' % (service_type, _MDNS_DOMAIN)
            info = self._zc.get_service_info(name, name)
            if info is not None:
                break
            elif attempt == CONF.mdns.lookup_attempts - 1:
                raise exception.ServiceLookupFailure(service=service_type)
            else:
                time.sleep(delay)
                delay *= 2

        all_addr = info.parsed_addresses()

        # Try to find the first routable address
        fallback = None
        for addr in all_addr:
            try:
                loopback = ipaddress.ip_address(addr).is_loopback
            except ValueError:
                LOG.debug('Skipping invalid IP address %s', addr)
                continue
            else:
                if loopback and skip_loopback:
                    LOG.debug('Skipping loopback IP address %s', addr)
                    continue

            if utils.get_route_source(addr, skip_link_local):
                address = addr
                break
            elif fallback is None:
                fallback = addr
        else:
            if fallback is None:
                raise exception.ServiceLookupFailure(
                    _('None of addresses %(addr)s for service %(service)s '
                      'are valid')
                    % {'addr': all_addr, 'service': service_type})
            else:
                LOG.warning('None of addresses %s seem routable, using %s',
                            all_addr, fallback)
                address = fallback

        properties = {}
        for key, value in info.properties.items():
            try:
                if isinstance(key, bytes):
                    key = key.decode('utf-8')
            except UnicodeError as exc:
                raise exception.ServiceLookupFailure(
                    _('Invalid properties for service %(svc)s. Cannot decode '
                      'key %(key)r: %(exc)r') %
                    {'svc': service_type, 'key': key, 'exc': exc})

            try:
                if isinstance(value, bytes):
                    value = value.decode('utf-8')
            except UnicodeError as exc:
                LOG.debug('Cannot convert value %(value)r for key %(key)s '
                          'to string, assuming binary: %(exc)s',
                          {'key': key, 'value': value, 'exc': exc})

            properties[key] = value

        path = properties.pop('path', '')
        protocol = properties.pop('protocol', None)
        if not protocol:
            if info.port == 80:
                protocol = 'http'
            else:
                protocol = 'https'

        if info.server.endswith('.local.'):
            # Local hostname means that the catalog lists an IP address,
            # so use it
            host = address
            if int(ipaddress.ip_address(host).version) == 6:
                host = '[%s]' % host
        else:
            # Otherwise use the provided hostname.
            host = info.server.rstrip('.')

        return ('{proto}://{host}:{port}{path}'.format(proto=protocol,
                                                       host=host,
                                                       port=info.port,
                                                       path=path),
                properties)

    def close(self):
        """Shut down mDNS and unregister services.

        .. note::
            If another server is running for the same services, it will
            re-register them immediately.
        """
        for info in self._registered:
            try:
                self._zc.unregister_service(info)
            except Exception:
                LOG.exception('Could not unregister mDNS service %s', info)
        self._zc.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


def _parse_endpoint(endpoint, service_type=None):
    params = {}
    url = urlparse.urlparse(endpoint)
    port = url.port

    if port is None:
        if url.scheme == 'https':
            port = 443
        else:
            port = 80

    addresses = []
    hostname = url.hostname
    try:
        infos = socket.getaddrinfo(hostname, port, 0, socket.IPPROTO_TCP)
    except socket.error as exc:
        raise exception.ServiceRegistrationFailure(
            service=service_type,
            error=_('Could not resolve hostname %(host)s: %(exc)s') %
            {'host': hostname, 'exc': exc})

    for info in infos:
        ip = info[4][0]
        if ip == hostname:
            # we need a host name for the service record. if what we have in
            # the catalog is an IP address, use the local hostname instead
            hostname = None
        # zeroconf requires addresses in network format
        ip = socket.inet_pton(info[0], ip)
        if ip not in addresses:
            addresses.append(ip)
    if not addresses:
        raise exception.ServiceRegistrationFailure(
            service=service_type,
            error=_('No suitable addresses found for %s') % url.hostname)

    # avoid storing information that can be derived from existing data
    if url.path not in ('', '/'):
        params['path'] = url.path

    if (not (port == 80 and url.scheme == 'http')
            and not (port == 443 and url.scheme == 'https')):
        params['protocol'] = url.scheme

    # zeroconf is pretty picky about having the trailing dot
    if hostname is not None and not hostname.endswith('.'):
        hostname += '.'

    return _endpoint(addresses, hostname, port, params)
