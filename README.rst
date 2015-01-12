Hardware properties discovery for OpenStack Ironic
==================================================

This is an auxiliary service for discovering basic hardware properties for a
node managed by `OpenStack Ironic`_. Hardware introspection or hardware
properties discovery is a process of getting hardware parameters required for
scheduling from a bare metal node, given it's power management credentials
(e.g. IPMI address, user name and password).

Support for *ironic-discoverd* is present in `Tuskar UI`_ -- OpenStack Horizon
plugin for installation of OpenStack using OpenStack technologies (TripleO_).

Hardware properties discovery flow using `Tuskar UI`_ is the following:

* User installs undercloud using e.g. instack-undercloud_ and logs into
  `Tuskar UI`_.

* User uploads CSV file with power credentials for all nodes.

* `Tuskar UI`_:

  * creates nodes in *Ironic* with power credentials populated,
  * sets maintenance mode for these nodes,
  * posts node UUID's to *ironic-discoverd*.

* On receiving node UUID's *ironic-discoverd*:

  * validates the nodes: their power credentials and current power state,
  * allows access to PXE boot service for the nodes,
  * issues reboot command for the nodes, so that they boot the
    *discovery ramdisk*.

* *Discovery ramdisk* collects the required information and posts it back to
  *ironic-discoverd*.

* On receiving data from the *discovery ramdisk*, *ironic-discoverd*:

  * validates received data,
  * finds the node in Ironic database using it's BMC address (MAC address in
    case of SSH driver),
  * fills missing node properties with received data and creates missing ports,
  * sets ``newly_discovered`` flag in node ``extra`` field to ``true``.

Starting *dnsmasq* and configuring PXE boot environment is not part of this
package and should be done separately.

*ironic-discoverd* requires OpenStack Juno (2014.2) release or newer.

Please use launchpad_ to report bugs and ask questions. Use PyPI_ for
downloads and accessing the released version of this README. Refer to
``CONTRIBUTING.rst`` for instructions on how to contribute.

.. _OpenStack Ironic: https://wiki.openstack.org/wiki/Ironic
.. _Tuskar UI: https://pypi.python.org/pypi/tuskar-ui
.. _TripleO: https://wiki.openstack.org/wiki/TripleO
.. _instack-undercloud: https://openstack.redhat.com/Deploying_an_RDO_Undercloud_with_Instack
.. _launchpad: https://bugs.launchpad.net/ironic-discoverd
.. _PyPI: https://pypi.python.org/pypi/ironic-discoverd

Installation
------------

*ironic-discoverd* is available as an RPM from Fedora 22 repositories or from
Juno RDO_ for Fedora 20, 21 and EPEL 7. It will be installed and preconfigured
if you used instack-undercloud_ to build your undercloud.
Otherwise after enabling required repositories install it using::

    yum install openstack-ironic-discoverd

and proceed with `Configuration`_.

Alternatively, you can install package from PyPI_ (you may want to use
virtualenv to isolate your environment)::

    pip install ironic-discoverd

.. _RDO: https://openstack.redhat.com/

Configuration
~~~~~~~~~~~~~

Copy ``example.conf`` to some permanent place
(``/etc/ironic-discoverd/discoverd.conf`` is what is used in the RPM).
Fill in at least configuration values with names starting with *os_*.
They configure how *ironic-discoverd* authenticates with Keystone.

Also set *database* option to where you want *ironic-discoverd* SQLite
database to be placed.

.. note::
    Configuration file contains a password and thus should be owned by ``root``
    and should have access rights like *0600*.

As for PXE boot environment, you need:

* TFTP server running and accessible.
* Build and put into your TFTP directory kernel and ramdisk from the
  diskimage-builder_ `ironic-discoverd-ramdisk element`_.
  You can also use `kernel`_ and `ramdisk`_ prepared for Instack.
* You need PXE boot server (e.g. *dnsmasq*) running on **the same** machine as
  *ironic-discoverd*. Don't do any firewall configuration: *ironic-discoverd*
  will handle it for you. In *ironic-discoverd* configuration file set
  ``dnsmasq_interface`` to the interface your PXE boot server listens on.
* Configure your ``$TFTPROOT/pxelinux.cfg/default`` with something like::

    default discover

    label discover
    kernel discovery.kernel
    append initrd=discovery.ramdisk discoverd_callback_url=http://{IP}:5050/v1/continue

    ipappend 3

  Replace ``{IP}`` with IP of the machine (do not use loopback interface, it
  will be accessed by ramdisk on a booting machine).

Use `ironic-discoverd element`_ as an example for this configuration.

.. _diskimage-builder: https://github.com/openstack/diskimage-builder
.. _ironic-discoverd-ramdisk element: https://github.com/openstack/diskimage-builder/tree/master/elements/ironic-discoverd-ramdisk
.. _ironic-discoverd element: https://github.com/agroup/instack-undercloud/tree/master/elements/ironic-discoverd
.. _kernel: https://repos.fedorapeople.org/repos/openstack-m/tripleo-images-rdo-juno/discovery-ramdisk.kernel
.. _ramdisk: https://repos.fedorapeople.org/repos/openstack-m/tripleo-images-rdo-juno/discovery-ramdisk.initramfs

Running
~~~~~~~

If you installed *ironic-discoverd* from the RPM, you already have a *systemd*
unit, so you can::

    systemctl enable openstack-ironic-discoverd
    systemctl start openstack-ironic-discoverd

Otherwise run as ``root``::

    ironic-discoverd /etc/ironic-discoverd/discoverd.conf

*ironic-discoverd* has a simple client library bundled within it.
It provides function ``ironic_discoverd.client.discover``, accepting list
of UUID's, ``base_url`` --- optional *ironic-discoverd* service URL and
``auth_token`` --- optional Keystone token.

You can also use it from CLI::

    python -m ironic_discoverd.client --auth-token TOKEN UUID1 UUID2

.. note::
    This CLI interface is not stable and may be changes without prior notice.

API
---

By default *ironic-discoverd* listens on ``0.0.0.0:5050``, this can be changed
in configuration. Protocol is JSON over HTTP.

HTTP API consist of 2 endpoints:

* ``POST /v1/discover`` initiate hardware discovery. Request body: JSON - list
  of UUID's of nodes to discover. All power management configuration for these
  nodes needs to be done prior to calling the endpoint. Requires X-Auth-Token
  header with Keystone token for authentication.

  Nodes will be put into maintenance mode during discovery. It's up to caller
  to put them back into use after discovery is done.

  .. note::
      Before version 0.2.0 this endpoint was not authenticated. Now it is,
      but check for admin role is not implemented yet - see `bug #1391866`_.

  Response:

  * 202 - accepted discovery request
  * 400 - bad request
  * 404 - node cannot be found

* ``POST /v1/continue`` internal endpoint for the discovery ramdisk to post
  back discovered data. Should not be used for anything other than implementing
  the ramdisk. Request body: JSON dictionary with keys:

  * ``cpus`` number of CPU
  * ``cpu_arch`` architecture of the CPU
  * ``memory_mb`` RAM in MiB
  * ``local_gb`` hard drive size in GiB
  * ``interfaces`` dictionary filled with data from all NIC's, keys being
    interface names, values being dictionaries with keys:

    * ``mac`` MAC address
    * ``ip`` IP address

  Response:

  * 200 - OK
  * 400 - bad request
  * 403 - node is not on discovery
  * 404 - node cannot be found or multiple nodes found

  Successful response body is a JSON dictionary with keys:

  * ``node`` node as returned by Ironic

.. _bug #1391866: https://bugs.launchpad.net/ironic-discoverd/+bug/1391866

Release Notes
-------------

1.0 Series
~~~~~~~~~~

1.0 is the first feature-complete release series. It's also the first series
to follow standard OpenStack processes from the beginning.

See `1.0.0 release tracking page`_ for details.

**API**

* ``/v1/continue`` is now sync:

  * Errors are properly returned to the caller
  * This call now returns value as a JSON dict

* Experimental support for updating IPMI credentials from within ramdisk.

  Enable via configuration option ``enable_setting_ipmi_credentials``.
  Beware that this feature lacks proper testing, is not supported
  officially yet and is subject to changes without keeping backward
  compatibility.

  See `setup-ipmi-credentials blueprint`_ for details.

* Add support for plugins that hook into data processing pipeline, see
  `plugin-architecture blueprint`_ for details.

* Add new API ``GET /v1/introspection/<uuid>`` and ``client.get_status`` for
  getting discovery status.

  See `get-status-api blueprint`_ for details.

**Configuration**

* Cache nodes under discovery in a local SQLite database. Set ``database``
  configuration option to where you want to place this database.
  Improves performance by making less calls to Ironic API and makes possible
  to get results of discovery.
* Discovery now times out by default, set ``timeout`` option to alter.
* Firewall management can be disabled completely via ``manage_firewall``
  option.

**Misc**

* Support for OpenStack Kilo release - see `Kilo state machine blueprint`_.
* Create ``CONTRIBUTING.rst``.

.. _1.0.0 release tracking page: https://bugs.launchpad.net/ironic-discoverd/+milestone/1.0.0
.. _setup-ipmi-credentials blueprint: https://blueprints.launchpad.net/ironic-discoverd/+spec/setup-ipmi-credentials
.. _plugin-architecture blueprint: https://blueprints.launchpad.net/ironic-discoverd/+spec/plugin-architecture
.. _get-status-api blueprint: https://blueprints.launchpad.net/ironic-discoverd/+spec/get-status-api
.. _Kilo state machine blueprint: https://blueprints.launchpad.net/ironic-discoverd/+spec/kilo-state-machine

0.2 Series
~~~~~~~~~~

0.2 is a long-term support series designed to work with OpenStack Juno
release. The major changes are:

**API**

* Authentication via Keystone for ``/v1/discover``.
* Expect ``interfaces`` instead of ``macs`` in post-back from the ramdisk
  **[version 0.2.1]**.
* If ``interfaces`` is present, only add ports for NIC's with IP address set
  **[version 0.2.1]**.
* ``/v1/discover`` now does some sync sanity checks **[version 0.2.2]**.
* ``discovery_timestamp`` is added to node extra on starting discovery
  **[version 0.2.2]**.
* Nodes will be always put into maintenance mode before discovery
  **[version 0.2.1]**.

**Configuration**

* Periodic firewall update is now configurable.
* On each start-up make several attempts to check that Ironic is available
  **[version 0.2.2]**.

**Misc**

* Simple client in ``ironic_discoverd.client``.
* Switch to Gerrit **[version 0.2.3]**, setuptools entry points and tox.
* Preliminary supported for Python 3.3 (real support depends on Eventlet).

0.1 Series
~~~~~~~~~~

First stable release series. Not supported any more.
