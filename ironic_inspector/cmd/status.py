# Copyright (c) 2018 NEC, Corp.
#
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

import sys

from oslo_config import cfg
from oslo_upgradecheck import common_checks
from oslo_upgradecheck import upgradecheck

from ironic_inspector.common.i18n import _
import ironic_inspector.conf as conf
from ironic_inspector import policy  # noqa Import for configuratiog loading.

CONF = conf.CONF


class Checks(upgradecheck.UpgradeCommands):

    """Upgrade checks for the ironic-status upgrade check command

    Upgrade checks should be added as separate methods in this class
    and added to _upgrade_checks tuple.
    """

    # A tuple of check tuples of (<name of check>, <check function>).
    # The name of the check will be used in the output of this command.
    # The check function takes no arguments and returns an
    # oslo_upgradecheck.upgradecheck.Result object with the appropriate
    # oslo_upgradecheck.upgradecheck.Code and details set. If the
    # check function hits warnings or failures then those should be stored
    # in the returned Result's "details" attribute. The
    # summary will be rolled up at the end of the check() method.
    _upgrade_checks = (
        # Added in Wallaby to raise visibility of the Victoria deprecation
        # of oslo.policy's json policy support.
        (_('Policy File JSON to YAML Migration'),
         (common_checks.check_policy_json, {'conf': CONF})),
    )


def main():
    return upgradecheck.main(
        cfg.CONF, project='ironic', upgrade_command=Checks())


if __name__ == '__main__':
    sys.exit(main())
