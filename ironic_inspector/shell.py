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

"""OpenStackClient plugin for ironic-inspector."""

from __future__ import print_function

import logging

from cliff import command
from cliff import show
from openstackclient.common import utils

from ironic_inspector import client


LOG = logging.getLogger('ironic_inspector.shell')
API_NAME = 'baremetal-introspection'
API_VERSION_OPTION = 'inspector_api_version'
DEFAULT_VERSION = '1'
API_VERSIONS = {
    "1": "ironic_inspector.shell",
}


def build_option_parser(parser):
    parser.add_argument('--inspector-api-version',
                        default=utils.env('INSPECTOR_VERSION',
                                          default=DEFAULT_VERSION),
                        help='inspector API version, only 1 is supported now '
                        '(env: INSPECTOR_VERSION).')
    return parser


class StartCommand(command.Command):
    """Start the introspection."""

    def get_parser(self, prog_name):
        parser = super(StartCommand, self).get_parser(prog_name)
        _add_common_arguments(parser)
        parser.add_argument('--new-ipmi-username',
                            default=None,
                            help='if set, *ironic-inspector* will update IPMI '
                            'user name to this value')
        parser.add_argument('--new-ipmi-password',
                            default=None,
                            help='if set, *ironic-inspector* will update IPMI '
                            'password to this value')
        return parser

    def take_action(self, parsed_args):
        auth_token = self.app.client_manager.auth_ref.auth_token
        client.introspect(parsed_args.uuid, base_url=parsed_args.inspector_url,
                          auth_token=auth_token,
                          new_ipmi_username=parsed_args.new_ipmi_username,
                          new_ipmi_password=parsed_args.new_ipmi_password)
        if parsed_args.new_ipmi_password:
            print('Setting IPMI credentials requested, please power on '
                  'the machine manually')


class StatusCommand(show.ShowOne):
    """Get introspection status."""

    def get_parser(self, prog_name):
        parser = super(StatusCommand, self).get_parser(prog_name)
        _add_common_arguments(parser)
        return parser

    def take_action(self, parsed_args):
        auth_token = self.app.client_manager.auth_ref.auth_token
        status = client.get_status(parsed_args.uuid,
                                   base_url=parsed_args.inspector_url,
                                   auth_token=auth_token)
        return zip(*sorted(status.items()))


def _add_common_arguments(parser):
    """Add commonly used arguments to a parser."""
    parser.add_argument('uuid', help='baremetal node UUID')
    # FIXME(dtantsur): this should be in build_option_parser, but then it won't
    # be available in commands
    parser.add_argument('--inspector-url',
                        default=utils.env('INSPECTOR_URL', default=None),
                        help='inspector URL, defaults to localhost '
                        '(env: INSPECTOR_URL).')
