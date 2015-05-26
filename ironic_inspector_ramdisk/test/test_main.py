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

import unittest

import mock
import requests

from ironic_inspector_ramdisk import discover
from ironic_inspector_ramdisk import main
from ironic_inspector_ramdisk.test import test_discover


FAKE_ARGS = test_discover.get_fake_args()


class TestParseArgs(unittest.TestCase):
    def test(self):
        args = ['http://url']
        parsed_args = main.parse_args(args)
        self.assertEqual('http://url', parsed_args.callback_url)

    def test_log_files(self):
        args = ['-L', 'log1', '-L', 'log2', 'url']
        parsed_args = main.parse_args(args)
        self.assertEqual(['log1', 'log2'],
                         parsed_args.system_log_file)


@mock.patch.object(main, 'setup_logging', lambda args: None)
@mock.patch.object(main, 'parse_args', return_value=FAKE_ARGS,
                   autospec=True)
@mock.patch.object(discover, 'setup_ipmi_credentials', autospec=True)
@mock.patch.object(discover, 'call_inspector', autospec=True,
                   return_value={})
@mock.patch.object(discover, 'collect_logs', autospec=True)
@mock.patch.object(discover, 'discover_hardware', autospec=True)
class TestMain(unittest.TestCase):
    def test_success(self, mock_discover, mock_logs, mock_callback,
                     mock_setup_ipmi, mock_parse):
        mock_logs.return_value = 'LOG'

        main.main()

        # FIXME(dtantsur): mock does not copy arguments, so the 2nd argument
        # actually is not what we expect ({})
        mock_discover.assert_called_once_with(FAKE_ARGS, mock.ANY, mock.ANY)
        mock_logs.assert_called_once_with(FAKE_ARGS)
        mock_callback.assert_called_once_with(FAKE_ARGS, {'logs': 'LOG'},
                                              mock.ANY)
        self.assertFalse(mock_setup_ipmi.called)

    def test_discover_fails(self, mock_discover, mock_logs, mock_callback,
                            mock_setup_ipmi, mock_parse):
        mock_logs.return_value = 'LOG'
        mock_discover.side_effect = RuntimeError('boom')

        self.assertRaisesRegexp(SystemExit, '1', main.main)

        mock_discover.assert_called_once_with(FAKE_ARGS, mock.ANY, mock.ANY)
        mock_logs.assert_called_once_with(FAKE_ARGS)
        mock_callback.assert_called_once_with(FAKE_ARGS, {'logs': 'LOG'},
                                              mock.ANY)
        failures = mock_callback.call_args[0][2]
        self.assertIn('boom', failures.get_error())

    def test_collect_logs_fails(self, mock_discover, mock_logs, mock_callback,
                                mock_setup_ipmi, mock_parse):
        mock_logs.side_effect = RuntimeError('boom')

        main.main()

        mock_discover.assert_called_once_with(FAKE_ARGS, mock.ANY, mock.ANY)
        mock_logs.assert_called_once_with(FAKE_ARGS)
        mock_callback.assert_called_once_with(FAKE_ARGS, {}, mock.ANY)

    def test_callback_fails(self, mock_discover, mock_logs, mock_callback,
                            mock_setup_ipmi, mock_parse):
        mock_logs.return_value = 'LOG'
        mock_callback.side_effect = requests.HTTPError('boom')

        self.assertRaisesRegexp(SystemExit, '1', main.main)

        mock_discover.assert_called_once_with(FAKE_ARGS, mock.ANY, mock.ANY)
        mock_logs.assert_called_once_with(FAKE_ARGS)
        mock_callback.assert_called_once_with(FAKE_ARGS, {'logs': 'LOG'},
                                              mock.ANY)

    def test_callback_fails2(self, mock_discover, mock_logs, mock_callback,
                             mock_setup_ipmi, mock_parse):
        mock_logs.return_value = 'LOG'
        mock_callback.side_effect = RuntimeError('boom')

        self.assertRaisesRegexp(SystemExit, '1', main.main)

        mock_discover.assert_called_once_with(FAKE_ARGS, mock.ANY, mock.ANY)
        mock_logs.assert_called_once_with(FAKE_ARGS)
        mock_callback.assert_called_once_with(FAKE_ARGS, {'logs': 'LOG'},
                                              mock.ANY)

    def test_setup_ipmi(self, mock_discover, mock_logs, mock_callback,
                        mock_setup_ipmi, mock_parse):
        mock_logs.return_value = 'LOG'
        mock_callback.return_value = {'ipmi_setup_credentials': True}

        main.main()

        mock_discover.assert_called_once_with(FAKE_ARGS, mock.ANY, mock.ANY)
        mock_logs.assert_called_once_with(FAKE_ARGS)
        mock_callback.assert_called_once_with(FAKE_ARGS, {'logs': 'LOG'},
                                              mock.ANY)
        mock_setup_ipmi.assert_called_once_with(mock_callback.return_value)

    def test_setup_ipmi_fails(self, mock_discover, mock_logs, mock_callback,
                              mock_setup_ipmi, mock_parse):
        mock_logs.return_value = 'LOG'
        mock_callback.return_value = {'ipmi_setup_credentials': True}
        mock_setup_ipmi.side_effect = RuntimeError('boom')

        self.assertRaisesRegexp(SystemExit, '1', main.main)

        mock_discover.assert_called_once_with(FAKE_ARGS, mock.ANY, mock.ANY)
        mock_logs.assert_called_once_with(FAKE_ARGS)
        mock_callback.assert_called_once_with(FAKE_ARGS, {'logs': 'LOG'},
                                              mock.ANY)
        mock_setup_ipmi.assert_called_once_with(mock_callback.return_value)
