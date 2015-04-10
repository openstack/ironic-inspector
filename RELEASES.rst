Release Notes
-------------

1.1 Series
~~~~~~~~~~

See `1.1.0 release tracking page`_ for details.

**Upgrade Notes**

* This version no longer supports ancient ramdisks that sent ``macs`` instead
  of ``interfaces``. It also raises exception if no valid interfaces were
  found after processing.

* ``identity_uri`` parameter should be set to Keystone admin endpoint.

* ``overwrite_existing`` is now enabled by default.

* Running the service as
  ::

    $ ironic-discoverd /path/to/config

  is no longer supported, use
  ::

    $ ironic-discoverd --config-file /path/to/config

**Major Features**

* Default to only creating a port for the NIC that the ramdisk was PXE booted
  from, if such information is provided by ramdisk as ``boot_interface`` field.
  Adjustable by ``add_ports`` option.

  See `better-boot-interface-detection blueprint
  <https://blueprints.launchpad.net/ironic-discoverd/+spec/better-boot-interface-detection>`_
  for details.

* `Setting IPMI Credentials`_ feature is considered stable now and is exposed
  in the client. It still needs to be enabled via configuration.

  See `setup-ipmi-credentials-take2 blueprint
  <https://blueprints.launchpad.net/ironic-discoverd/+spec/setup-ipmi-credentials-take2>`_
  for what changed since 1.0.0 (tl;dr: everything).

* Proper CLI tool implemented as a plugin for OpenStackClient_.

  Also client now properly sets error message from the server in its exception.
  This might be a breaking change, if you relied on exception message
  previously.

* The default value for ``overwrite_existing`` configuration option was
  flipped, matching the default behavior for Ironic inspection.

* Switch to `oslo.config <http://docs.openstack.org/developer/oslo.config/>`_
  for configuration management (many thanks to Yuiko Takada).

**Other Changes**

* New option ``add_ports`` allows precise control over which ports to add,
  replacing deprecated ``ports_for_inactive_interfaces``.

* Experimental plugin ``edeploy`` to use with `eDeploy hardware detection and
  classification utilities`_.

  See `eDeploy blueprint`_ for details.

* Plugin ``root_device_hint`` for in-band root device discovery.

* Plugin ``ramdisk_error`` is now enabled by default.

* Serious authentication issues were fixed, ``keystonemiddleware`` is a new
  requirement.

* Basic support for i18n via oslo.i18n.

**Known Issues**

.. _1.1.0 release tracking page: https://bugs.launchpad.net/ironic-discoverd/+milestone/1.1.0
.. _Setting IPMI Credentials: https://github.com/stackforge/ironic-discoverd#setting-ipmi-credentials
.. _OpenStackClient: http://docs.openstack.org/developer/python-openstackclient/
.. _eDeploy hardware detection and classification utilities: https://pypi.python.org/pypi/hardware
.. _eDeploy blueprint: https://blueprints.launchpad.net/ironic-discoverd/+spec/edeploy

1.0 Series
~~~~~~~~~~

1.0 is the first feature-complete release series. It's also the first series
to follow standard OpenStack processes from the beginning. All 0.2 series
users are advised to upgrade.

See `1.0.0 release tracking page`_ for details.

**1.0.1 release**

This maintenance fixed serious problem with authentication and unfortunately
brought new upgrade requirements:

* Dependency on *keystonemiddleware*;
* New configuration option ``identity_uri``, defaulting to localhost.

**Upgrade notes**

Action required:

* Fill in ``database`` option in the configuration file before upgrading.
* Stop relying on **ironic-discoverd** setting maintenance mode itself.
* Stop relying on ``discovery_timestamp`` node extra field.

Action recommended:

* Switch your init scripts to use ``ironic-discoverd --config-file <path>``
  instead of just ``ironic-discoverd <path>``.

* Stop relying on ``on_discovery`` and ``newly_discovered`` being set in node
  ``extra`` field during and after introspection. Use new get status HTTP
  endpoint and client API instead.

* Switch from ``discover`` to ``introspect`` HTTP endpoint and client API.

**Major features**

* Introspection now times out by default, set ``timeout`` option to alter.

* New API ``GET /v1/introspection/<uuid>`` and ``client.get_status`` for
  getting discovery status.

  See `get-status-api blueprint`_ for details.

* New API ``POST /v1/introspection/<uuid>`` and ``client.introspect``
  is now used to initiate discovery, ``/v1/discover`` is deprecated.

  See `v1 API reform blueprint`_ for details.

* ``/v1/continue`` is now sync:

  * Errors are properly returned to the caller
  * This call now returns value as a JSON dict (currently empty)

* Add support for plugins that hook into data processing pipeline. Refer to
  Plugins_ for information on bundled plugins and to CONTRIBUTING.rst_ for
  information on how to write your own.

  See `plugin-architecture blueprint`_ for details.

* Support for OpenStack Kilo release and new Ironic state machine -
  see `Kilo state machine blueprint`_.

  As a side effect, no longer depend on maintenance mode for introspection.
  Stop putting node in maintenance mode before introspection.

* Cache nodes under introspection in a local SQLite database.
  ``database`` configuration option sets where to place this database.
  Improves performance by making less calls to Ironic API and makes possible
  to get results of introspection.

**Other Changes**

* Firewall management can be disabled completely via ``manage_firewall``
  option.

* Experimental support for updating IPMI credentials from within ramdisk.

  Enable via configuration option ``enable_setting_ipmi_credentials``.
  Beware that this feature lacks proper testing, is not supported
  officially yet and is subject to changes without keeping backward
  compatibility.

  See `setup-ipmi-credentials blueprint`_ for details.

**Known Issues**

* `bug 1415040 <https://bugs.launchpad.net/ironic-discoverd/+bug/1415040>`_
  it is required to set IP addresses instead of host names in
  ``ipmi_address``/``ilo_address``/``drac_host`` node ``driver_info`` field
  for **ironic-discoverd** to work properly.

.. _1.0.0 release tracking page: https://bugs.launchpad.net/ironic-discoverd/+milestone/1.0.0
.. _setup-ipmi-credentials blueprint: https://blueprints.launchpad.net/ironic-discoverd/+spec/setup-ipmi-credentials
.. _Plugins: https://github.com/stackforge/ironic-discoverd#plugins
.. _CONTRIBUTING.rst: https://github.com/stackforge/ironic-discoverd/blob/master/CONTRIBUTING.rst
.. _plugin-architecture blueprint: https://blueprints.launchpad.net/ironic-discoverd/+spec/plugin-architecture
.. _get-status-api blueprint: https://blueprints.launchpad.net/ironic-discoverd/+spec/get-status-api
.. _Kilo state machine blueprint: https://blueprints.launchpad.net/ironic-discoverd/+spec/kilo-state-machine
.. _v1 API reform blueprint: https://blueprints.launchpad.net/ironic-discoverd/+spec/v1-api-reform

0.2 Series
~~~~~~~~~~

0.2 series is designed to work with OpenStack Juno release.
Not supported any more.

0.1 Series
~~~~~~~~~~

First stable release series. Not supported any more.
