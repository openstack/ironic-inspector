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

import ssl
import sys

from futurist import periodics
from oslo_config import cfg
from oslo_log import log

from ironic_inspector.common import ironic as ir_utils
from ironic_inspector import db
from ironic_inspector import firewall
from ironic_inspector import main as app
from ironic_inspector import node_cache
from ironic_inspector.plugins import base as plugins_base
from ironic_inspector import utils


LOG = log.getLogger(__name__)
CONF = cfg.CONF


class WSGIService(object):
    """Provides ability to launch API from wsgi app."""

    def __init__(self):
        self.app = app.app
        self._periodics_worker = None

    def _init_middleware(self):
        """Initialize WSGI middleware.

        :returns: None
        """

        if CONF.auth_strategy != 'noauth':
            utils.add_auth_middleware(self.app)
        else:
            LOG.warning('Starting unauthenticated, please check'
                        ' configuration')

        # TODO(aarefiev): move to WorkerService once we split service
        if CONF.processing.store_data == 'none':
            LOG.warning('Introspection data will not be stored. Change '
                        '"[processing] store_data" option if this is not '
                        'the desired behavior')
        elif CONF.processing.store_data == 'swift':
            LOG.info('Introspection data will be stored in Swift in the '
                     'container %s', CONF.swift.container)
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

    # TODO(aarefiev): move init code to WorkerService
    def _init_host(self):
        """Initialize Worker host

        Init db connection, load and validate processing
        hooks, runs periodic tasks.

        :returns None
        """
        db.init()

        try:
            hooks = plugins_base.validate_processing_hooks()
        except Exception as exc:
            LOG.critical(str(exc))
            sys.exit(1)

        LOG.info('Enabled processing hooks: %s', [h.name for h in hooks])

        if CONF.firewall.manage_firewall:
            firewall.init()

        periodic_update_ = periodics.periodic(
            spacing=CONF.firewall.firewall_update_period,
            enabled=CONF.firewall.manage_firewall
        )(periodic_update)
        periodic_clean_up_ = periodics.periodic(
            spacing=CONF.clean_up_period
        )(periodic_clean_up)

        self._periodics_worker = periodics.PeriodicWorker(
            callables=[(periodic_update_, None, None),
                       (periodic_clean_up_, None, None)],
            executor_factory=periodics.ExistingExecutor(utils.executor()))
        utils.executor().submit(self._periodics_worker.start)

    def shutdown(self):
        """Stop serving API, clean up.

        :returns: None
        """
        # TODO(aarefiev): move shutdown code to WorkerService
        LOG.debug('Shutting down')

        firewall.clean_up()

        if self._periodics_worker is not None:
            try:
                self._periodics_worker.stop()
                self._periodics_worker.wait()
            except Exception as e:
                LOG.exception('Service error occurred when stopping '
                              'periodic workers. Error: %s', e)
            self._periodics_worker = None

        if utils.executor().alive:
            utils.executor().shutdown(wait=True)

        LOG.info('Shut down successfully')

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

        self._init_host()

        try:
            self.app.run(**app_kwargs)
        finally:
            self.shutdown()


def periodic_update():  # pragma: no cover
    try:
        firewall.update_filters()
    except Exception:
        LOG.exception('Periodic update of firewall rules failed')


def periodic_clean_up():  # pragma: no cover
    try:
        if node_cache.clean_up():
            firewall.update_filters()
        sync_with_ironic()
    except Exception:
        LOG.exception('Periodic clean up of node cache failed')


def sync_with_ironic():
    ironic = ir_utils.get_client()
    # TODO(yuikotakada): pagination
    ironic_nodes = ironic.node.list(limit=0)
    ironic_node_uuids = {node.uuid for node in ironic_nodes}
    node_cache.delete_nodes_not_in_list(ironic_node_uuids)
