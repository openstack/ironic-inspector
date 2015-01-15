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

"""Base code for plugins support."""

import abc

import six
from stevedore import named

from ironic_discoverd import conf


@six.add_metaclass(abc.ABCMeta)
class ProcessingHook(object):  # pragma: no cover
    """Abstract base class for introspection data processing hooks."""

    def before_processing(self, node_info):
        """Hook to run before any other data processing.

        This hook is run even before sanity checks.

        :param node_info: raw information sent by the ramdisk, may be modified
                          by the hook.
        :returns: nothing.
        """

    def before_update(self, node, ports, node_info):
        """Hook to run before Ironic node update.

        This hook is run after node is found and ports are created,
        just before the node is updated with the data.

        :param node: Ironic node as returned by the Ironic client, should not
                     be modified directly by the hook.
        :param ports: Ironic ports created by discoverd, also should not be
                      updated directly.
        :param node_info: processed data from the ramdisk.
        :returns: tuple (node patches, port patches) where
                  *node_patches* is a list of JSON patches [RFC 6902] to apply
                  to the node, *port_patches* is a dict where keys are
                  port MAC's, values are lists of JSON patches, e.g.
                  ::
                      (
                       [{'op': 'add', 'path': '/extra/foo', 'value': 'bar'}],
                       {'11:22:33:44:55:55': [
                            {'op': 'add', 'path': '/extra/foo', 'value': 'bar'}
                        ]}
                      )
                  [RFC 6902] - http://tools.ietf.org/html/rfc6902
        """


_HOOKS_MGR = None


def processing_hooks_manager(*args):
    """Create a Stevedore extension manager for processing hooks.

    :param args: arguments to pass to the hooks constructor.
    """
    global _HOOKS_MGR
    if _HOOKS_MGR is None:
        names = [x.strip()
                 for x in conf.get('discoverd', 'processing_hooks').split(',')
                 if x.strip()]
        _HOOKS_MGR = named.NamedExtensionManager('ironic_discoverd.hooks',
                                                 names=names,
                                                 invoke_on_load=True,
                                                 invoke_args=args,
                                                 name_order=True)
    return _HOOKS_MGR
