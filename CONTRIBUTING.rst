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

Using simple ramdisk
~~~~~~~~~~~~~~~~~~~~

::

    [[local|localrc]]
    enable_service ironic ir-api ir-cond
    disable_service n-net n-novnc
    enable_service neutron q-svc q-agt q-dhcp q-l3 q-meta
    enable_service s-proxy s-object s-container s-account
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

Using IPA
~~~~~~~~~

::

    [[local|localrc]]
    enable_service ironic ir-api ir-cond
    disable_service n-net n-novnc
    enable_service neutron q-svc q-agt q-dhcp q-l3 q-meta
    enable_service s-proxy s-object s-container s-account
    disable_service heat h-api h-api-cfn h-api-cw h-eng
    disable_service cinder c-sch c-api c-vol

    enable_plugin ironic-inspector https://github.com/openstack/ironic-inspector

    IRONIC_BAREMETAL_BASIC_OPS=True
    IRONIC_VM_COUNT=2
    IRONIC_VM_SPECS_RAM=1024
    IRONIC_DEPLOY_FLAVOR="fedora ironic-agent"

    IRONIC_INSPECTOR_RAMDISK_FLAVOR="fedora ironic-agent"

    VIRT_DRIVER=ironic

    LOGDAYS=1
    LOGFILE=~/logs/stack.sh.log
    SCREEN_LOGDIR=~/logs/screen

    DEFAULT_INSTANCE_TYPE=baremetal
    TEMPEST_ALLOW_TENANT_ISOLATION=False

Notes
-----

* Set IRONIC_INSPECTOR_BUILD_RAMDISK to True if you want to build ramdisk.
  Default value is False and ramdisk will be download instead of building.

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
  ``before_update(introspection_data,node_info,**)``
      called after node is found and ports are created, but before data is
      updated on a node.  Please refer to the docstring for details
      and examples.

      .. note::
        Keyword arguments node_patches and port_patches are also provided, but
        should not be used in new plugins.

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

* **ironic-inspector**  allows more condition types to be added for
  `Introspection Rules`_. Inherit ``RuleConditionPlugin`` class defined in
  ironic_inspector.plugins.base_ module and overwrite at least the following
  method:

  ``check(node_info,field,params,**)``
      called to check that condition holds for a given field. Field value is
      provided as ``field`` argument, ``params`` is a dictionary defined
      at the time of condition creation. Returns boolean value.

  The following methods and attributes may also be overridden:

  ``validate(params,**)``
      called to validate parameters provided during condition creating.
      Default implementation requires keys listed in ``REQUIRED_PARAMS`` (and
      only them).

  ``REQUIRED_PARAMS``
      contains set of required parameters used in the default implementation
      of ``validate`` method, defaults to ``value`` parameter.

  ``ALLOW_NONE``
      if it's set to ``True``, missing fields will be passed as ``None``
      values instead of failing the condition. Defaults to ``False``.

  Make your plugin a setuptools entry point under
  ``ironic_inspector.rules.conditions`` namespace.

* **ironic-inspector** allows more action types to be added for `Introspection
  Rules`_. Inherit ``RuleActionPlugin`` class defined in
  ironic_inspector.plugins.base_ module and overwrite at least the following
  method:

  ``apply(node_info,params,**)``
      called to apply the action.

  The following methods and attributes may also be overridden:

  ``rollback(node_info,params,**)``
      called to clean up when conditions were not met.
      Default implementation does nothing.

  ``validate(params,**)``
      called to validate parameters provided during actions creating.
      Default implementation requires keys listed in ``REQUIRED_PARAMS`` (and
      only them).

  ``REQUIRED_PARAMS``
      contains set of required parameters used in the default implementation
      of ``validate`` method, defaults to no parameters.

  Make your plugin a setuptools entry point under
  ``ironic_inspector.rules.conditions`` namespace.

.. note::
    ``**`` argument is needed so that we can add optional arguments without
    breaking out-of-tree plugins. Please make sure to include and ignore it.

.. _ironic_inspector.plugins.base: https://github.com/openstack/ironic-inspector/blob/master/ironic_inspector/plugins/base.py
.. _Introspection Rules: https://github.com/openstack/ironic-inspector#introspection-rules

Adding migrations to the database
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

In order to make any changes to the database, you must add a new migration.
This can be done using alembic::

    alembic --config ironic_inspector/alembic.ini revision -m "A short description"

This will generate an empty migration file, with the correct revision
information already included. In this file there are two functions:

* upgrade - The upgrade function is run when
    ``ironic-inspector-dbsync upgrade`` is run, and should be populated with
    code to bring the database up to its new state from the state it was in
    after the last migration.

* downgrade - The downgrade function should have code to undo the actions which
    upgrade performs, returning the database to the state it would have been in
    before the migration ran.

For further information on creating a migration, refer to
`Create a Migration Script`_ from the alembic documentation.

.. _Create a Migration Script: https://alembic.readthedocs.org/en/latest/tutorial.html#create-a-migration-script
