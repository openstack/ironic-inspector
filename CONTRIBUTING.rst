=================
How To Contribute
=================

Basics
~~~~~~

* Our source code is hosted on `OpenStack GitHub`_, but please do not send pull
  requests there.

* Please follow usual OpenStack `Gerrit Workflow`_ to submit a patch.

* Update change log in README.rst on any significant change.

* It goes without saying that any code change should by accompanied by unit
  tests.

* Note the branch you're proposing changes to. ``master`` is the current focus
  of development, use ``stable/VERSION`` for proposing an urgent fix, where
  ``VERSION`` is the current stable series. E.g. at the moment of writing the
  stable branch is ``stable/1.0``.

* Please file a launchpad_ blueprint for any significant code change and a bug
  for any significant bug fix.

.. _OpenStack GitHub: https://github.com/openstack/ironic-inspector
.. _Gerrit Workflow: http://docs.openstack.org/infra/manual/developers.html#development-workflow
.. _launchpad: https://bugs.launchpad.net/ironic-inspector

Development Environment
~~~~~~~~~~~~~~~~~~~~~~~

First of all, install *tox* utility. It's likely to be in your distribution
repositories under name of ``python-tox``. Alternatively, you can install it
from PyPI.

Next checkout and create environments::

    git clone https://github.com/openstack/ironic-inspector.git
    cd ironic-inspector
    tox

Repeat *tox* command each time you need to run tests. If you don't have Python
interpreter of one of supported versions (currently 2.7 and 3.4), use
``-e`` flag to select only some environments, e.g.

::

    tox -e py27

.. note::
    Support for Python 3 is highly experimental, stay with Python 2 for the
    production environment for now.

There is a simple functional test that involves fetching the ramdisk from
Github::

    tox -e func

Run the service with::

    .tox/py27/bin/ironic-inspector --config-file example.conf

Of course you may have to modify ``example.conf`` to match your OpenStack
environment.

You can develop and test **ironic-inspector** using DevStack - see
`DevStack Support`_ for the current status.

DevStack Support
~~~~~~~~~~~~~~~~

`DevStack <http://docs.openstack.org/developer/devstack/>`_ provides a way to
quickly build full OpenStack development environment with requested
components. There is a plugin for installing **ironic-inspector** on DevStack.

Example local.conf
------------------

::

    [[local|localrc]]
    enable_service ironic ir-api ir-cond
    disable_service n-net n-novnc
    enable_service neutron q-svc q-agt q-dhcp q-l3 q-meta
    disable_service heat h-api h-api-cfn h-api-cw h-eng
    disable_service cinder c-sch c-api c-vol

    enable_plugin ironic-inspector https://github.com/openstack/ironic-inspector

    IRONIC_BAREMETAL_BASIC_OPS=True
    IRONIC_VM_COUNT=2
    IRONIC_VM_SPECS_RAM=1024
    IRONIC_DEPLOY_FLAVOR="fedora deploy-ironic"

    IRONIC_INSPECTOR_RAMDISK_FLAVOR="fedora ironic-discoverd-ramdisk"

    VIRT_DRIVER=ironic

    LOGDAYS=1
    LOGFILE=~/logs/stack.sh.log
    SCREEN_LOGDIR=~/logs/screen

    DEFAULT_INSTANCE_TYPE=baremetal
    TEMPEST_ALLOW_TENANT_ISOLATION=False

Notes
-----

* Replace "fedora" with whatever you have

* You need at least 1G of RAM for VMs, default value of 512 MB won't work

* Network configuration is pretty sensitive, better not to touch it
  without deep understanding

* This configuration disables Heat and Cinder, adjust it if you need these
  services

* Before restarting stack.sh::

    rm -rf /opt/stack/ironic-inspector

Test
----

There is a test script included::

    source devstack/openrc admin admin
    /opt/stack/ironic-inspector/devstack/exercise.sh

Usage
-----

Start introspection for a node manually::

    source devstack/openrc admin admin
    openstack baremetal introspection start <UUID>

Then check status via API::

    openstack baremetal introspection status <UUID>

Writing a Plugin
~~~~~~~~~~~~~~~~

* **ironic-inspector** allows you to hook code into the data processing chain
  after introspection. Inherit ``ProcessingHook`` class defined in
  ironic_inspector.plugins.base_ module and overwrite any or both of
  the following methods:

  ``before_processing(introspection_data,**)``
      called before any data processing, providing the raw data. Each plugin in
      the chain can modify the data, so order in which plugins are loaded
      matters here. Returns nothing.
  ``before_update(introspection_data,node_info,node_patches,ports_patches,**)``
      called after node is found and ports are created, but before data is
      updated on a node. ``node_patches`` and ``ports_patches`` are JSON
      patches for node and ports to apply.
      Please refer to the docstring for details and examples.

  Make your plugin a setuptools entry point under
  ``ironic_inspector.hooks.processing`` namespace and enable it in the
  configuration file (``processing.processing_hooks`` option).

* **ironic-inspector** allows plugins to override the action when node is not
  found in node cache. Write a callable with the following signature:

  ``(introspection_data,**)``
    called when node is not found in cache, providing the processed data.
    Should return a ``NodeInfo`` class instance.

  Make your plugin a setuptools entry point under
  ``ironic_inspector.hooks.node_not_found`` namespace and enable it in the
  configuration file (``processing.node_not_found_hook`` option).

.. note::
    ``**`` argument is needed so that we can add optional arguments without
    breaking out-of-tree plugins. Please make sure to include and ignore it.

.. _ironic_inspector.plugins.base: https://github.com/openstack/ironic-inspector/blob/master/ironic_inspector/plugins/base.py
