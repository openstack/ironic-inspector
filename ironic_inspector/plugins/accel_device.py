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

"""Gather and distinguish Accelerator PCI devices from inventory."""

from oslo_config import cfg
import yaml

from ironic_inspector.plugins import base
from ironic_inspector import utils


CONF = cfg.CONF
LOG = utils.getProcessingLogger(__name__)


class AccelDevicesHook(base.ProcessingHook):
    """Processing hook for distinguishing accelerator devices."""

    def __init__(self):
        super(AccelDevicesHook, self).__init__()
        self._known_devices = {}
        with open(CONF.accelerators.known_devices) as f:
            self._known_devices = yaml.safe_load(f)
        self._validate_datasource()

    def _validate_datasource(self):
        # Do a simple check against the data source
        if (not self._known_devices or
                'pci_devices' not in self._known_devices):
            raise RuntimeError('Could not find pci_devices in the '
                               'configuration data')
        if not isinstance(self._known_devices['pci_devices'], list):
            raise RuntimeError('pci_devices should contain a list of devices')
        for device in self._known_devices['pci_devices']:
            if not device.get('vendor_id') or not device.get('device_id'):
                raise RuntimeError('one of devices is missing vendor_id or '
                                   'device_id')

    def _find_accelerator(self, vendor_id, device_id):
        for dev in self._known_devices['pci_devices']:
            if (dev['vendor_id'] == vendor_id and
                    dev['device_id'] == device_id):
                return dev

    def before_update(self, introspection_data, node_info, **kwargs):
        pci_devices = introspection_data.get('pci_devices', [])
        if not pci_devices:
            LOG.warning('Unable to distinguish accelerator devices due to no '
                        'PCI devices information was received from the '
                        'ramdisk.')
            return

        accelerators = []
        for pci_dev in pci_devices:
            dev = self._find_accelerator(pci_dev['vendor_id'],
                                         pci_dev['product_id'])
            if dev:
                accel = {k: dev[k] for k in dev.keys()}
                accel.update(pci_address=pci_dev['bus'])
                accelerators.append(accel)

        if accelerators:
            node_info.update_properties(accelerators=accelerators)
            LOG.info('Found the following accelerator devices: %s',
                     accelerators)
        else:
            LOG.info('No known accelerator devices found')
