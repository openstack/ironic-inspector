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

from oslo_config import cfg

from ironic_inspector.common.i18n import _
from ironic_inspector.common import keystone


IRONIC_GROUP = 'ironic'
SERVICE_TYPE = 'baremetal'


_OPTS = [
    cfg.StrOpt('os_region',
               help=_('Keystone region used to get Ironic endpoints.'),
               deprecated_for_removal=True,
               deprecated_reason=_("Use [ironic]/region_name option instead "
                                   "to configure region.")),
    cfg.StrOpt('auth_strategy',
               default='keystone',
               choices=('keystone', 'noauth'),
               help=_('Method to use for authentication: noauth or '
                      'keystone.'),
               deprecated_for_removal=True,
               deprecated_reason=_("Use [ironic]/auth_type, for noauth case "
                                   "set [ironic]/auth_type to `none` and "
                                   "specify ironic API URL via "
                                   "[ironic]/endpoint_override option.")),
    cfg.StrOpt('ironic_url',
               default='http://localhost:6385/',
               help=_('Ironic API URL, used to set Ironic API URL when '
                      'auth_strategy option is noauth or auth_type is "none" '
                      'to work with standalone Ironic without keystone.'),
               deprecated_for_removal=True,
               deprecated_reason=_('Use [ironic]/endpoint_override option '
                                   'to set a specific ironic API url.')),
    cfg.StrOpt('os_service_type',
               default='baremetal',
               help=_('Ironic service type.'),
               deprecated_for_removal=True,
               deprecated_reason=_('Use [ironic]/service_type option '
                                   'to set a specific type.')),
    cfg.StrOpt('os_endpoint_type',
               default='internalURL',
               help=_('Ironic endpoint type.'),
               deprecated_for_removal=True,
               deprecated_reason=_('Use [ironic]/valid_interfaces option '
                                   'to specify endpoint interfaces.')),
    cfg.IntOpt('retry_interval',
               default=2,
               help=_('Interval between retries in case of conflict error '
                      '(HTTP 409).')),
    cfg.IntOpt('max_retries',
               default=30,
               help=_('Maximum number of retries in case of conflict error '
                      '(HTTP 409).')),
]


def register_opts(conf):
    conf.register_opts(_OPTS, IRONIC_GROUP)
    keystone.register_auth_opts(IRONIC_GROUP, SERVICE_TYPE)


def list_opts():
    return keystone.add_auth_options(_OPTS, SERVICE_TYPE)
