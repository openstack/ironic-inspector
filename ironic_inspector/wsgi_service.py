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

import signal
import ssl
import sys

import eventlet
from oslo_config import cfg
from oslo_log import log
from oslo_service import service

from ironic_inspector.common.rpc_service import RPCService
from ironic_inspector import main as app
from ironic_inspector import utils

LOG = log.getLogger(__name__)
CONF = cfg.CONF


class WSGIService(object):
    """Provides ability to launch API from wsgi app."""

    def __init__(self):
        self.app = app.app
        signal.signal(signal.SIGHUP, self._handle_sighup)
        signal.signal(signal.SIGTERM, self._handle_sigterm)
        self.rpc_service = RPCService(CONF.host)

    def _init_middleware(self):
        """Initialize WSGI middleware.

        :returns: None
        """

        if CONF.auth_strategy != 'noauth':
            utils.add_auth_middleware(self.app)
        else:
            LOG.warning('Starting unauthenticated, please check'
                        ' configuration')
        utils.add_cors_middleware(self.app)

    def _create_ssl_context(self):
        if not CONF.use_ssl:
            return

        MIN_VERSION = (2, 7, 9)

        if sys.version_info < MIN_VERSION:
            LOG.warning(('Unable to use SSL in this version of Python: '
                         '%(current)s, please ensure your version of Python '
                         'is greater than %(min)s to enable this feature.'),
                        {'current': '.'.join(map(str, sys.version_info[:3])),
                         'min': '.'.join(map(str, MIN_VERSION))})
            return

        context = ssl.create_default_context(purpose=ssl.Purpose.CLIENT_AUTH)
        if CONF.ssl_cert_path and CONF.ssl_key_path:
            try:
                context.load_cert_chain(CONF.ssl_cert_path, CONF.ssl_key_path)
            except IOError as exc:
                LOG.warning('Failed to load certificate or key from defined '
                            'locations: %(cert)s and %(key)s, will continue '
                            'to run with the default settings: %(exc)s',
                            {'cert': CONF.ssl_cert_path,
                             'key': CONF.ssl_key_path,
                             'exc': exc})
            except ssl.SSLError as exc:
                LOG.warning('There was a problem with the loaded certificate '
                            'and key, will continue to run with the default '
                            'settings: %s', exc)
        return context

    def shutdown(self, error=None):
        """Stop serving API.

        :returns: None
        """
        LOG.debug('Shutting down')
        self.rpc_service.stop()
        sys.exit(error)

    def run(self):
        """Start serving this service using loaded application.

        :returns: None
        """
        app_kwargs = {'host': CONF.listen_address,
                      'port': CONF.listen_port}

        context = self._create_ssl_context()
        if context:
            app_kwargs['ssl_context'] = context

        self._init_middleware()

        LOG.info('Spawning RPC service')
        service.launch(CONF, self.rpc_service,
                       restart_method='mutate')

        try:
            self.app.run(**app_kwargs)
        except Exception as e:
            self.shutdown(error=str(e))
        else:
            self.shutdown()

    def _handle_sighup_bg(self, *args):
        """Reload config on SIGHUP."""
        CONF.mutate_config_files()

    def _handle_sighup(self, *args):
        eventlet.spawn(self._handle_sighup_bg, *args)

    def _handle_sigterm(self, *args):
        # This is a workaround to ensure that shutdown() is done when recieving
        # SIGTERM. Raising KeyboardIntrerrupt which won't be caught by any
        # 'except Exception' clauses.
        raise KeyboardInterrupt
