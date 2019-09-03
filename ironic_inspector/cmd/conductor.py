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

"""The Ironic Inspector Conductor service."""

import sys

from oslo_config import cfg
from oslo_service import service

from ironic_inspector.common.i18n import _
from ironic_inspector.common.rpc_service import RPCService
from ironic_inspector.common import service_utils

CONF = cfg.CONF


def main(args=sys.argv[1:]):
    # Parse config file and command line options, then start logging
    service_utils.prepare_service(args)

    if CONF.standalone:
        msg = _('To run ironic-inspector-conductor, [DEFAULT]standalone '
                'should be set to False.')
        sys.exit(msg)

    launcher = service.ServiceLauncher(CONF, restart_method='mutate')
    launcher.launch_service(RPCService(CONF.host))
    launcher.wait()


if __name__ == '__main__':
    sys.exit(main())
