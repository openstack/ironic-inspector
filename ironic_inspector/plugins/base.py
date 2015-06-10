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

from oslo_config import cfg
import six
from stevedore import driver
from stevedore import named


CONF = cfg.CONF


@six.add_metaclass(abc.ABCMeta)
class ProcessingHook(object):  # pragma: no cover
    """Abstract base class for introspection data processing hooks."""

    def before_processing(self, introspection_data, **kwargs):
        """Hook to run before any other data processing.

        This hook is run even before sanity checks.

        :param introspection_data: raw information sent by the ramdisk,
                                   may be modified by the hook.
        :param kwargs: used for extensibility without breaking existing hooks
        :returns: nothing.
        """

    def before_update(self, introspection_data, node_info, node_patches,
                      ports_patches, **kwargs):
        """Hook to run before Ironic node update.

        This hook is run after node is found and ports are created,
        just before the node is updated with the data.

        To update node and/or ports use *node_patches* and *ports_patches*
        arguments.

        :param introspection_data: processed data from the ramdisk.
        :param node_info: NodeInfo instance.
        :param node_patches: list of JSON patches [RFC 6902] to apply
                             to the node, e.g.
                             ::
                               [{'op': 'add',
                                 'path': '/extra/foo',
                                 'value': 'bar'}]
        :param ports_patches: dict where keys are port MAC's,
                              values are lists of JSON patches, e.g.
                              ::
                                {'11:22:33:44:55:55': [
                                  {'op': 'add', 'path': '/extra/foo',
                                  'value': 'bar'}
                                ]}
        :param kwargs: used for extensibility without breaking existing hooks
        :returns: nothing.

        [RFC 6902] - http://tools.ietf.org/html/rfc6902
        """


_HOOKS_MGR = None
_NOT_FOUND_HOOK_MGR = None


def processing_hooks_manager(*args):
    """Create a Stevedore extension manager for processing hooks.

    :param args: arguments to pass to the hooks constructor.
    """
    global _HOOKS_MGR
    if _HOOKS_MGR is None:
        names = [x.strip()
                 for x in CONF.processing.processing_hooks.split(',')
                 if x.strip()]
        _HOOKS_MGR = named.NamedExtensionManager(
            'ironic_inspector.hooks.processing',
            names=names,
            invoke_on_load=True,
            invoke_args=args,
            name_order=True)
    return _HOOKS_MGR


def node_not_found_hook_manager(*args):
    global _NOT_FOUND_HOOK_MGR
    if _NOT_FOUND_HOOK_MGR is None:
        name = CONF.processing.node_not_found_hook
        if name:
            _NOT_FOUND_HOOK_MGR = driver.DriverManager(
                'ironic_inspector.hooks.node_not_found',
                name=name)

    return _NOT_FOUND_HOOK_MGR
