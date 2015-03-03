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
  **ironic-discoverd** `HTTP API`_ or again via `Tuskar UI`_.

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

* Separate `HTTP API`_ can be used to query introspection results for a given
  node.

Starting DHCP server and configuring PXE boot environment is not part of this
package and should be done separately.

.. _instack-undercloud: https://openstack.redhat.com/Deploying_an_RDO_Undercloud_with_Instack

Installation
------------

**ironic-discoverd** is available as an RPM from Fedora 22 repositories or from
Juno RDO_ for Fedora 20, 21 and EPEL 7. It will be installed and preconfigured
if you used instack-undercloud_ to build your undercloud.
Otherwise after enabling required repositories install it using::

    yum install openstack-ironic-discoverd

Alternatively (e.g. if you need the latest version), you can install package
from PyPI_ (you may want to use virtualenv to isolate your environment)::

    pip install ironic-discoverd

The third way for RPM-based distros is to use `ironic-discoverd copr`_ which
contains **unstable** git snapshots of **ironic-discoverd**.

.. _RDO: https://openstack.redhat.com/
.. _ironic-discoverd copr: https://copr.fedoraproject.org/coprs/divius/ironic-discoverd/

Configuration
~~~~~~~~~~~~~

Copy ``example.conf`` to some permanent place
(``/etc/ironic-discoverd/discoverd.conf`` is what is used in the RPM).
Fill in at least configuration values with names starting with ``os_`` and
``identity_uri``.  They configure how **ironic-discoverd** authenticates
with Keystone and checks authentication of clients.

Also set *database* option to where you want **ironic-discoverd** SQLite
database to be placed.

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

  You need diskimage-builder_ 0.1.38 or newer to do it.

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

**ironic-discoverd** has a simple client library bundled within it.
It provides functions:

* ``ironic_discoverd.client.introspect`` for starting introspection
* ``ironic_discoverd.client.get_status`` for querying introspection status

both accepting:

``uuid``
    node UUID
``base_url``
    optional **ironic-discoverd** service URL (defaults to ``127.0.0.1:5050``)
``auth_token``
    optional Keystone token.

For testing purposes you can also use it from CLI::

    python -m ironic_discoverd.client --auth-token TOKEN introspect UUID
    python -m ironic_discoverd.client --auth-token TOKEN get_status UUID

.. note::
    This CLI interface is not stable and may be changed without prior notice.
    Proper supported CLI is `expected later
    <https://bugs.launchpad.net/ironic-discoverd/+bug/1410180>`_.

HTTP API
~~~~~~~~

By default **ironic-discoverd** listens on ``0.0.0.0:5050``, port
can be changed in configuration. Protocol is JSON over HTTP.

The HTTP API consist of these endpoints:

* ``POST /v1/introspection/<UUID>`` initiate hardware discovery for node
  ``<UUID>``. All power management configuration for this node needs to be done
  prior to calling the endpoint.

  Requires X-Auth-Token header with Keystone token for authentication.

  Response:

  * 202 - accepted discovery request
  * 400 - bad request
  * 401, 403 - missing or invalid authentication
  * 404 - node cannot be found

  Client library function: ``ironic_discoverd.client.introspect``.

* ``GET /v1/introspection/<UUID>`` get hardware discovery status.

  Requires X-Auth-Token header with Keystone token for authentication.

  Response:

  * 200 - OK
  * 400 - bad request
  * 401, 403 - missing or invalid authentication
  * 404 - node cannot be found

  Response body: JSON dictionary with keys:

  * ``finished`` (boolean) whether discovery is finished
  * ``error`` error string or ``null``

  Client library function: ``ironic_discoverd.client.get_status``.

* ``POST /v1/continue`` internal endpoint for the discovery ramdisk to post
  back discovered data. Should not be used for anything other than implementing
  the ramdisk. Request body: JSON dictionary with at least these keys:

  * ``cpus`` number of CPU
  * ``cpu_arch`` architecture of the CPU
  * ``memory_mb`` RAM in MiB
  * ``local_gb`` hard drive size in GiB
  * ``interfaces`` dictionary filled with data from all NIC's, keys being
    interface names, values being dictionaries with keys:

    * ``mac`` MAC address
    * ``ip`` IP address

  .. note::
        This list highly depends on enabled plugins, provided above are
        expected keys for the default set of plugins. See Plugins_ for details.

  Response:

  * 200 - OK
  * 400 - bad request
  * 403 - node is not on introspection
  * 404 - node cannot be found or multiple nodes found

Plugins
~~~~~~~

**ironic-discoverd** heavily relies on plugins for data processing. Even the
standard functionality is largely based on plugins. Set ``processing_hooks``
option in the configuration file to change the set of plugins to be run on
introspection data. Note that order does matter in this option.

These are plugins that are enabled by default and should not be disabled,
unless you understand what you're doing:

``scheduler``
    validates and updates basic hardware scheduling properties: CPU number and
    architecture, memory and disk size.
``validate_interfaces``
    validates network interfaces information.

Here are some plugins that can be additionally enabled:

``ramdisk_error``
    reports error, if ``error`` field is set by the ramdisk.
``example``
    example plugin logging it's input and output.

Refer to CONTRIBUTING.rst_ for information on how to write your own plugin.

Release Notes
-------------

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
* Fill in ``identity_uri`` field in the configuration.

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
The major changes are:

**API**

* Authentication via Keystone for ``/v1/discover``.
* Expect ``interfaces`` instead of ``macs`` in post-back from the ramdisk
  **[version 0.2.1]**.
* If ``interfaces`` is present, only add ports for NIC's with IP address set
  **[version 0.2.1]**.
* ``/v1/discover`` now does some sync sanity checks **[version 0.2.2]**.
* Nodes will be always put into maintenance mode before discovery
  **[version 0.2.1]**.

**Configuration**

* Periodic firewall update is now configurable.
* On each start-up make several attempts to check that Ironic is available
  **[version 0.2.2]**.

**Misc**

* Simple client in ``ironic_discoverd.client``.
* Preliminary supported for Python 3.3 (real support depends on Eventlet).

0.1 Series
~~~~~~~~~~

First stable release series. Not supported any more.
