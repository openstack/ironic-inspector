# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.
"""WSGI script for Ironic Inspector API, installed by pbr."""

import sys

from oslo_config import cfg

from ironic_inspector.common.i18n import _
from ironic_inspector.common import service_utils
from ironic_inspector import main

CONF = cfg.CONF


def initialize_wsgi_app():
    # Parse config file and command line options, then start logging
    service_utils.prepare_service(sys.argv[1:])

    if CONF.standalone:
        msg = _('To run ironic-inspector-api, [DEFAULT]standalone should be '
                'set to False.')
        sys.exit(msg)

    return main.get_app()
