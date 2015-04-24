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

import argparse
import logging
import sys

import requests

from ironic_discoverd_ramdisk import discover


LOG = logging.getLogger('ironic-discoverd-ramdisk')


def parse_args(args):
    parser = argparse.ArgumentParser(description='Detect present hardware.')
    parser.add_argument('-p', '--port', type=int, default=8080,
                        help='Port to serve logs over HTTP')
    parser.add_argument('-L', '--system-log-file', action='append',
                        help='System log file to be sent to discoverd, may be '
                        'specified multiple times')
    parser.add_argument('-l', '--log-file', default='discovery-logs',
                        help='Path to log file, defaults to ./discovery-logs')
    parser.add_argument('-d', '--daemonize-on-failure', action='store_true',
                        help='In case of failure, fork off, continue running '
                        'and serve logs via port set by --port')
    parser.add_argument('--bootif', help='PXE boot interface')
    # Support for edeploy plugin
    parser.add_argument('--use-hardware-detect', action='store_true',
                        help='Use hardware-detect utility from '
                        'python-hardware package')
    parser.add_argument('--benchmark', action='store_true',
                        help='Enables benchmarking for hardware-detect')
    # ironic-discoverd callback
    parser.add_argument('callback_url',
                        help='Full ironic-discoverd callback URL')
    return parser.parse_args(args)


def setup_logging(args):
    format = '%(asctime)s %(levelname)s: %(name)s: %(message)s'
    logging.basicConfig(filename=args.log_file, filemode='w',
                        level=logging.DEBUG, format=format)
    hnd = logging.StreamHandler()
    hnd.setLevel(logging.WARNING)
    formatter = logging.Formatter('%(levelname)s: %(message)s')
    hnd.setFormatter(formatter)
    logging.getLogger().addHandler(hnd)


def main():
    args = parse_args(sys.argv[1:])
    data = {}
    setup_logging(args)
    failures = discover.AccumulatedFailure()

    try:
        discover.discover_hardware(args, data, failures)
    except Exception as exc:
        LOG.exception('failed to discover data')
        failures.add(exc)

    try:
        data['logs'] = discover.collect_logs(args)
    except Exception:
        LOG.exception('failed to collect logs')

    call_error = True
    resp = {}
    try:
        resp = discover.call_discoverd(args, data, failures)
    except requests.RequestException as exc:
        LOG.error('%s when calling to discoverd', exc)
    except Exception:
        LOG.exception('failed to call discoverd')
    else:
        call_error = False

    if resp.get('ipmi_setup_credentials'):
        try:
            discover.setup_ipmi_credentials(resp)
        except Exception:
            LOG.exception('failed to set IPMI credentials')
            call_error = True

    if failures or call_error:
        if args.daemonize_on_failure:
            discover.fork_and_serve_logs(args)
        sys.exit(1)
