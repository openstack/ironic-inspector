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

"""Generic LLDP Processing Hook"""

import binascii

from ironicclient import exc as client_exc
import netaddr
from oslo_config import cfg

from ironic_inspector.common.i18n import _LW, _LE
from ironic_inspector.common import ironic
from ironic_inspector.plugins import base
from ironic_inspector import utils

LOG = utils.getProcessingLogger(__name__)

# NOTE(sambetts) Constants defined according to IEEE standard for LLDP
# http://standards.ieee.org/getieee802/download/802.1AB-2009.pdf
LLDP_TLV_TYPE_CHASSIS_ID = 1
LLDP_TLV_TYPE_PORT_ID = 2
PORT_ID_SUBTYPE_MAC = 3
PORT_ID_SUBTYPE_IFNAME = 5
PORT_ID_SUBTYPE_LOCAL = 7
STRING_PORT_SUBTYPES = [PORT_ID_SUBTYPE_IFNAME, PORT_ID_SUBTYPE_LOCAL]
CHASSIS_ID_SUBTYPE_MAC = 4

CONF = cfg.CONF

REQUIRED_IRONIC_VERSION = '1.19'


class GenericLocalLinkConnectionHook(base.ProcessingHook):
    """Process mandatory LLDP packet fields

    Non-vendor specific LLDP packet fields processed for each NIC found for a
    baremetal node, port ID and chassis ID. These fields if found and if valid
    will be saved into the local link connection info port id and switch id
    fields on the Ironic port that represents that NIC.
    """

    def _get_local_link_patch(self, tlv_type, tlv_value, port):
        try:
            data = bytearray(binascii.unhexlify(tlv_value))
        except TypeError:
            LOG.warning(_LW("TLV value for TLV type %d not in correct"
                            "format, ensure TLV value is in "
                            "hexidecimal format when sent to "
                            "inspector"), tlv_type)
            return

        item = value = None
        if tlv_type == LLDP_TLV_TYPE_PORT_ID:
            # Check to ensure the port id is an allowed type
            item = "port_id"
            if data[0] in STRING_PORT_SUBTYPES:
                value = data[1:].decode()
            if data[0] == PORT_ID_SUBTYPE_MAC:
                value = str(netaddr.EUI(
                    binascii.hexlify(data[1:]).decode(),
                    dialect=netaddr.mac_unix_expanded))
        elif tlv_type == LLDP_TLV_TYPE_CHASSIS_ID:
            # Check to ensure the chassis id is the allowed type
            if data[0] == CHASSIS_ID_SUBTYPE_MAC:
                item = "switch_id"
                value = str(netaddr.EUI(
                    binascii.hexlify(data[1:]).decode(),
                    dialect=netaddr.mac_unix_expanded))

        if item and value:
            if (not CONF.processing.overwrite_existing and
                    item in port.local_link_connection):
                return
            return {'op': 'add',
                    'path': '/local_link_connection/%s' % item,
                    'value': value}

    def before_update(self, introspection_data, node_info, **kwargs):
        """Process LLDP data and patch Ironic port local link connection"""
        inventory = utils.get_inventory(introspection_data)

        ironic_ports = node_info.ports()

        for iface in inventory['interfaces']:
            if iface['name'] not in introspection_data['all_interfaces']:
                continue

            mac_address = iface['mac_address']
            port = ironic_ports.get(mac_address)
            if not port:
                LOG.debug("Skipping LLC processing for interface %s, matching "
                          "port not found in Ironic.", mac_address,
                          node_info=node_info, data=introspection_data)
                continue

            lldp_data = iface.get('lldp')
            if lldp_data is None:
                LOG.warning(_LW("No LLDP Data found for interface %s"),
                            mac_address, node_info=node_info,
                            data=introspection_data)
                continue

            patches = []
            for tlv_type, tlv_value in lldp_data:
                patch = self._get_local_link_patch(tlv_type, tlv_value, port)
                if patch is not None:
                    patches.append(patch)

            try:
                # NOTE(sambetts) We need a newer version of Ironic API for this
                # transaction, so create a new ironic client and explicitly
                # pass it into the function.
                cli = ironic.get_client(api_version=REQUIRED_IRONIC_VERSION)
                node_info.patch_port(port, patches, ironic=cli)
            except client_exc.NotAcceptable:
                LOG.error(_LE("Unable to set Ironic port local link "
                              "connection information because Ironic does not "
                              "support the required version"),
                          node_info=node_info, data=introspection_data)
                # NOTE(sambetts) May as well break out out of the loop here
                # because Ironic version is not going to change for the other
                # interfaces.
                break
