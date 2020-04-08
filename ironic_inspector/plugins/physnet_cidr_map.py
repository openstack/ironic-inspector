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

"""Port Physical Network Hook"""

import ipaddress

from oslo_config import cfg

from ironic_inspector.plugins import base_physnet

CONF = cfg.CONF


class PhysnetCidrMapHook(base_physnet.BasePhysnetHook):
    """Process port physical network

    Set the physical_network field of baremetal ports based on a cidr to
    physical network mapping in the configuration.
    """

    def get_physnet(self, port, iface_name, introspection_data):
        """Return a physical network to apply to a port.

        :param port: The ironic port to patch.
        :param iface_name: Name of the interface.
        :param introspection_data: Introspection data.
        :returns: The physical network to set, or None.
        """

        def get_iface_ips(iface):
            ips = []
            for addr_version in ['ipv4_address', 'ipv6_address']:
                try:
                    ips.append(ipaddress.ip_address(iface.get(addr_version)))
                except ValueError:
                    pass

            return ips

        # Convert list config to a dict with ip_networks as keys
        cidr_map = {
            ipaddress.ip_network(x.rsplit(':', 1)[0]): x.rsplit(':', 1)[1]
            for x in CONF.port_physnet.cidr_map}

        iface = [i for i in introspection_data['inventory']['interfaces']
                 if i['name'] == iface_name][0]
        ips = get_iface_ips(iface)

        for ip in ips:
            try:
                return [cidr_map[cidr] for cidr in cidr_map if ip in cidr][0]
            except IndexError:
                # No mapping found for any of the ip addresses
                return None
