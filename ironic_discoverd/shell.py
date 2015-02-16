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

"""OpenStackClient plugin for ironic-discoverd."""

import logging

from cliff import command
from cliff import show
from openstackclient.common import utils

from ironic_discoverd import client


LOG = logging.getLogger('ironic_discoverd.shell')
API_NAME = 'baremetal-introspection'
API_VERSION_OPTION = 'discoverd_api_version'
DEFAULT_VERSION = '1'


def build_option_parser(parser):
    parser.add_argument('--discoverd-api-version',
                        default=utils.env('DISCOVERD_VERSION',
                                          default=DEFAULT_VERSION),
                        help='discoverd API version, only 1 is supported now '
                        '(env: DISCOVERD_VERSION).')
    return parser


class StartCommand(command.Command):
    """Start the introspection."""

    def get_parser(self, prog_name):
        parser = super(StartCommand, self).get_parser(prog_name)
        _add_common_arguments(parser)
        parser.add_argument('--new-ipmi-username',
                            default=None,
                            help='if set, *ironic-discoverd* will update IPMI '
                            'user name to this value')
        parser.add_argument('--new-ipmi-password',
                            default=None,
                            help='if set, *ironic-discoverd* will update IPMI '
                            'password to this value')
        return parser

    def take_action(self, parsed_args):
        auth_token = self.app.client_manager.auth_ref.auth_token
        client.introspect(parsed_args.uuid, base_url=parsed_args.discoverd_url,
                          auth_token=auth_token,
                          new_ipmi_username=parsed_args.new_ipmi_username,
                          new_ipmi_password=parsed_args.new_ipmi_password)


class StatusCommand(show.ShowOne):
    """Get introspection status."""

    def get_parser(self, prog_name):
        parser = super(StatusCommand, self).get_parser(prog_name)
        _add_common_arguments(parser)
        return parser

    def take_action(self, parsed_args):
        auth_token = self.app.client_manager.auth_ref.auth_token
        status = client.get_status(parsed_args.uuid,
                                   base_url=parsed_args.discoverd_url,
                                   auth_token=auth_token)
        return zip(*sorted(status.items()))


def _add_common_arguments(parser):
    """Add commonly used arguments to a parser."""
    parser.add_argument('uuid', help='baremetal node UUID')
    # FIXME(dtantsur): this should be in build_option_parser, but then it won't
    # be available in commands
    parser.add_argument('--discoverd-url',
                        default=utils.env('DISCOVERD_URL', default=None),
                        help='discoverd URL, defaults to localhost '
                        '(env: DISCOVERD_URL).')
