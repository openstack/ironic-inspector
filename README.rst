Hardware introspection for OpenStack Ironic
===========================================

This is an auxiliary service for discovering hardware properties for a
node managed by `OpenStack Ironic`_. Hardware introspection or hardware
properties discovery is a process of getting hardware parameters required for
scheduling from a bare metal node, given it's power management credentials
(e.g. IPMI address, user name and password).

A special *discovery ramdisk* is required to collect the information on a
node. The default one can be built using diskimage-builder_ and
`ironic-discoverd-ramdisk element`_ (see Configuration_ below).

Support for **ironic-discoverd** is present in `Tuskar UI`_ --
OpenStack Horizon plugin for TripleO_.

**ironic-discoverd** requires OpenStack Juno (2014.2) release or newer.

Please use launchpad_ to report bugs and ask questions. Use PyPI_ for
downloads and accessing the released version of this README. Refer to
CONTRIBUTING.rst_ for instructions on how to contribute.

.. _OpenStack Ironic: https://wiki.openstack.org/wiki/Ironic
.. _Tuskar UI: https://pypi.python.org/pypi/tuskar-ui
.. _TripleO: https://wiki.openstack.org/wiki/TripleO
.. _launchpad: https://bugs.launchpad.net/ironic-discoverd
.. _PyPI: https://pypi.python.org/pypi/ironic-discoverd
.. _CONTRIBUTING.rst: https://github.com/stackforge/ironic-discoverd/blob/master/CONTRIBUTING.rst

Workflow
--------

Usual hardware introspection flow is as follows:

* Operator installs undercloud with **ironic-discoverd**
  (e.g. using instack-undercloud_).

* Operator enrolls nodes into Ironic either manually or by uploading CSV file
  to `Tuskar UI`_. Power management credentials should be provided to Ironic
  at this step.

* Operator sends nodes on introspection either manually using
  **ironic-discoverd** API (see Usage_) or again via `Tuskar UI`_.

* On receiving node UUID **ironic-discoverd**:

  * validates node power credentials, current power and provisioning states,
  * allows firewall access to PXE boot service for the nodes,
  * issues reboot command for the nodes, so that they boot the
    discovery ramdisk.

* The discovery ramdisk collects the required information and posts it back
  to **ironic-discoverd**.

* On receiving data from the discovery ramdisk, **ironic-discoverd**:

  * validates received data,
  * finds the node in Ironic database using it's BMC address (MAC address in
    case of SSH driver),
  * fills missing node properties with received data and creates missing ports.

* Separate API (see Usage_) can be used to query introspection results
  for a given node.

Starting DHCP server and configuring PXE boot environment is not part of this
package and should be done separately.

.. _instack-undercloud: https://www.rdoproject.org/Deploying_an_RDO_Undercloud_with_Instack

Installation
------------

**ironic-discoverd** is available as an RPM from Fedora 22 repositories or from
Juno (and later) `RDO <https://www.rdoproject.org/>`_ for Fedora 20, 21
and EPEL 7.  It will be installed and preconfigured if you used
instack-undercloud_ to build your undercloud.
Otherwise after enabling required repositories install it using::

    yum install openstack-ironic-discoverd

To install only Python packages (including the client), use::

    yum install python-ironic-discoverd

Alternatively (e.g. if you need the latest version), you can install package
from PyPI_ (you may want to use virtualenv to isolate your environment)::

    pip install ironic-discoverd

Finally, there is a `DevStack <http://docs.openstack.org/developer/devstack/>`_
plugin for **ironic-discoverd** - see
https://etherpad.openstack.org/p/DiscoverdDevStack for the current status.

Configuration
~~~~~~~~~~~~~

Copy ``example.conf`` to some permanent place
(``/etc/ironic-discoverd/discoverd.conf`` is what is used in the RPM).
Fill in at least these configuration values:

* ``os_username``, ``os_password``, ``os_tenant_name`` - Keystone credentials
  to use when accessing other services and check client authentication tokens;

* ``os_auth_url``, ``identity_uri`` - Keystone endpoints for validating
  authentication tokens and checking user roles;

* ``database`` - where you want **ironic-discoverd** SQLite database
  to be placed;

* ``dnsmasq_interface`` - interface on which ``dnsmasq`` (or another DHCP
  service) listens for PXE boot requests (defaults to ``br-ctlplane`` which is
  a sane default for TripleO_ based installations but is unlikely to work for
  other cases).

See comments inside `example.conf
<https://github.com/stackforge/ironic-discoverd/blob/master/example.conf>`_
for the other possible configuration options.

.. note::
    Configuration file contains a password and thus should be owned by ``root``
    and should have access rights like ``0600``.

As for PXE boot environment, you'll need:

* TFTP server running and accessible (see below for using *dnsmasq*).
  Ensure ``pxelinux.0`` is present in the TFTP root.

* Build and put into your TFTP directory kernel and ramdisk from the
  diskimage-builder_ `ironic-discoverd-ramdisk element`_::

    ramdisk-image-create -o discovery fedora ironic-discoverd-ramdisk

  You need diskimage-builder_ 0.1.38 or newer to do it (using the latest one
  is always advised).

* You need PXE boot server (e.g. *dnsmasq*) running on **the same** machine as
  **ironic-discoverd**. Don't do any firewall configuration:
  **ironic-discoverd** will handle it for you. In **ironic-discoverd**
  configuration file set ``dnsmasq_interface`` to the interface your
  PXE boot server listens on. Here is an example *dnsmasq.conf*::

    port=0
    interface={INTERFACE}
    bind-interfaces
    dhcp-range={DHCP IP RANGE, e.g. 192.168.0.50,192.168.0.150}
    enable-tftp
    tftp-root={TFTP ROOT, e.g. /tftpboot}
    dhcp-boot=pxelinux.0

* Configure your ``$TFTPROOT/pxelinux.cfg/default`` with something like::

    default discover

    label discover
    kernel discovery.kernel
    append initrd=discovery.initramfs discoverd_callback_url=http://{IP}:5050/v1/continue

    ipappend 3

  Replace ``{IP}`` with IP of the machine (do not use loopback interface, it
  will be accessed by ramdisk on a booting machine).

  .. note::
    There are some prebuilt images which use obsolete ``ironic_callback_url``
    instead of ``discoverd_callback_url``. Modify ``pxelinux.cfg/default``
    accordingly if you have one of these.

Here is *discoverd.conf* you may end up with::

    [discoverd]
    debug = false
    identity_uri = http://127.0.0.1:35357
    os_auth_url = http://127.0.0.1:5000/v2.0
    os_username = admin
    os_password = password
    os_tenant_name = admin
    dnsmasq_interface = br-ctlplane

.. note::
    Set ``debug = true`` if you want to see complete logs.

.. _diskimage-builder: https://github.com/openstack/diskimage-builder
.. _ironic-discoverd-ramdisk element: https://github.com/openstack/diskimage-builder/tree/master/elements/ironic-discoverd-ramdisk

Running
~~~~~~~

If you installed **ironic-discoverd** from the RPM, you already have
a *systemd* unit, so you can::

    systemctl enable openstack-ironic-discoverd
    systemctl start openstack-ironic-discoverd

Otherwise run as ``root``::

    ironic-discoverd --config-file /etc/ironic-discoverd/discoverd.conf

.. note::
    Running as ``root`` is not required if **ironic-discoverd** does not
    manage the firewall (i.e. ``manage_firewall`` is set to ``false`` in the
    configuration file).

A good starting point for writing your own *systemd* unit should be `one used
in Fedora <http://pkgs.fedoraproject.org/cgit/openstack-ironic-discoverd.git/plain/openstack-ironic-discoverd.service>`_.

Usage
-----

**ironic-discoverd** has a simple client library for Python and a CLI tool
bundled with it.

Client library is in module ``ironic_discoverd.client``, every call
accepts additional optional arguments:

* ``base_url`` **ironic-discoverd** API endpoint, defaults to
  ``127.0.0.1:5050``,
* ``auth_token`` Keystone authentication token.

CLI tool is based on OpenStackClient_ with prefix
``openstack baremetal introspection``. Accepts optional argument
``--discoverd-url`` with the **ironic-discoverd** API endpoint.

* **Start introspection on a node**:

  ``introspect(uuid, new_ipmi_username=None, new_ipmi_password=None)``

  ::

    $ openstack baremetal introspection start UUID [--new-ipmi-password=PWD [--new-ipmi-username=USER]]

  * ``uuid`` - Ironic node UUID;
  * ``new_ipmi_username`` and ``new_ipmi_password`` - if these are set,
    **ironic-discoverd** will switch to manual power on and assigning IPMI
    credentials on introspection. See `Setting IPMI Credentials`_ for details.

* **Query introspection status**:

  ``get_status(uuid)``

  ::

    $ openstack baremetal introspection status UUID

  * ``uuid`` - Ironic node UUID.

Refer to HTTP-API.rst_ for information on the HTTP API.

.. _OpenStackClient: http://docs.openstack.org/developer/python-openstackclient/
.. _HTTP-API.rst: https://github.com/stackforge/ironic-discoverd/blob/master/HTTP-API.rst
.. _HTTP API: https://github.com/stackforge/ironic-discoverd/blob/master/HTTP-API.rst

Setting IPMI Credentials
~~~~~~~~~~~~~~~~~~~~~~~~

If you have physical access to your nodes, you can use **ironic-discoverd** to
set IPMI credentials for them without knowing the original ones. The workflow
is as follows:

* Ensure nodes will PXE boot on the right network by default.

* Set ``enable_setting_ipmi_credentials = true`` in the **ironic-discoverd**
  configuration file.

* Enroll nodes in Ironic with setting their ``ipmi_address`` only. This step
  allows **ironic-discoverd** to distinguish nodes.

* Set maintenance mode on nodes. That's an important step, otherwise Ironic
  might interfere with introspection process.

* Start introspection with providing additional parameters:

  * ``new_ipmi_password`` IPMI password to set,
  * ``new_ipmi_username`` IPMI user name to set, defaults to one in node
    driver_info.

* Manually power on the nodes and wait.

* After introspection is finished (watch nodes power state or use
  **ironic-discoverd** status API) you can turn maintenance mode off.

Note that due to various limitations on password value in different BMC,
**ironic-discoverd** will only accept passwords with length between 1 and 20
consisting only of letters and numbers.

Plugins
~~~~~~~

**ironic-discoverd** heavily relies on plugins for data processing. Even the
standard functionality is largely based on plugins. Set ``processing_hooks``
option in the configuration file to change the set of plugins to be run on
introspection data. Note that order does matter in this option.

These are plugins that are enabled by default and should not be disabled,
unless you understand what you're doing:

``ramdisk_error``
    reports error, if ``error`` field is set by the ramdisk.
``scheduler``
    validates and updates basic hardware scheduling properties: CPU number and
    architecture, memory and disk size.
``validate_interfaces``
    validates network interfaces information.

Here are some plugins that can be additionally enabled:

``example``
    example plugin logging it's input and output.
``root_device_hint``
    gathers block devices from ramdisk and exposes root device in multiple
    runs.
``edeploy``
    plugin for `eDeploy hardware detection and classification utilities`_,
    requires a `special ramdisk`__.

Refer to CONTRIBUTING.rst_ for information on how to write your own plugin.

.. _eDeploy hardware detection and classification utilities: https://pypi.python.org/pypi/hardware
__ https://github.com/rdo-management/instack-undercloud/tree/master/elements/ironic-discoverd-ramdisk-instack

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
