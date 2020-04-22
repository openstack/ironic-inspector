# Copyright (c) 2017 StackHPC Ltd.
#
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

import abc

from openstack import exceptions
from oslo_config import cfg

from ironic_inspector.plugins import base
from ironic_inspector import utils

LOG = utils.getProcessingLogger(__name__)

CONF = cfg.CONF


class BasePhysnetHook(base.ProcessingHook):
    """Base class for plugins that assign a physical network to ports.

    The mechanism for mapping a port to a physical network should be provided
    by a subclass via the get_physnet() method.
    """

    @abc.abstractmethod
    def get_physnet(self, port, iface_name, introspection_data):
        """Return a physical network to apply to a port.

        Subclasses should implement this method to determine how to map a port
        to a physical network.

        :param port: The ironic port to patch.
        :param iface_name: Name of the interface.
        :param introspection_data: Introspection data.
        :returns: The physical network to set, or None.
        """

    def _get_physnet_patch(self, physnet, port):
        """Return a patch to update the port's physical network.

        :param physnet: The physical network to set.
        :param port: The ironic port to patch.
        :returns: A dict to be used as a patch for the port, or None.
        """
        if (not CONF.processing.overwrite_existing
                or port.physical_network == physnet):
            return
        return {'op': 'add', 'path': '/physical_network', 'value': physnet}

    def before_update(self, introspection_data, node_info, **kwargs):
        """Process introspection data and patch port physical network."""
        inventory = utils.get_inventory(introspection_data)

        ironic_ports = node_info.ports()

        for iface in inventory['interfaces']:
            if iface['name'] not in introspection_data['all_interfaces']:
                continue

            mac_address = iface['mac_address']
            port = ironic_ports.get(mac_address)
            if not port:
                LOG.debug("Skipping physical network processing for interface "
                          "%s, matching port not found in Ironic.",
                          mac_address,
                          node_info=node_info, data=introspection_data)
                continue

            # Determine the physical network for this port.
            # Port not touched in here.
            physnet = self.get_physnet(port, iface['name'], introspection_data)
            if physnet is None:
                LOG.debug("Skipping physical network processing for interface "
                          "%s, no physical network mapping",
                          mac_address,
                          node_info=node_info, data=introspection_data)
                continue

            patch = self._get_physnet_patch(physnet, port)
            if patch is None:
                LOG.debug("Skipping physical network processing for interface "
                          "%s, no update required",
                          mac_address,
                          node_info=node_info, data=introspection_data)
                continue

            try:
                node_info.patch_port(port, [patch])
            except exceptions.BadRequestException as e:
                LOG.warning("Failed to update port %(uuid)s: %(error)s",
                            {'uuid': port.uuid, 'error': e},
                            node_info=node_info)
