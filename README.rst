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

.. note::
    Configuration file contains a password and thus should be owned by ``root``
    and should have access rights like *0600*.

As for PXE boot environment, you need:

* TFTP server running and accessible.
* Build and put into your TFTP directory kernel and ramdisk from the
  diskimage-builder_ `discovery-ironic element`_.
  You can also use `kernel`_ and `ramdisk`_ prepared for Instack.
* You need PXE boot server (e.g. *dnsmasq*) running on **the same** machine as
  *ironic-discoverd*. Don't do any firewall configuration: *ironic-discoverd*
  will handle it for you. In *ironic-discoverd* configuration file set
  ``dnsmasq_interface`` to the interface your PXE boot server listens on.
* Configure your ``$TFTPROOT/pxelinux.cfg/default`` with something like::

    default discover

    label discover
    kernel discovery.kernel
    append initrd=discovery.ramdisk
    ironic_callback_url=http://{IP}:5050/v1/continue

    ipappend 3

  Replace ``{IP}`` with IP of the machine (do not use loopback interface, it
  will be accessed by ramdisk on a booting machine).

Use `ironic-discoverd element`_ as an example for this configuration.

.. _diskimage-builder: https://github.com/openstack/diskimage-builder
.. _discovery-ironic element: https://github.com/agroup/instack-undercloud/tree/master/elements/discovery-ironic
.. _ironic-discoverd element: https://github.com/agroup/instack-undercloud/tree/master/elements/ironic-discoverd
.. _kernel: http://file.rdu.redhat.com/%7Ejslagle/tripleo-images-juno-source/discovery-ramdisk.kernel
.. _ramdisk: http://file.rdu.redhat.com/%7Ejslagle/tripleo-images-juno-source/discovery-ramdisk.initramfs

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

API
---

By default *ironic-discoverd* listens on ``0.0.0.0:5050``, this can be changed
in configuration. Protocol is JSON over HTTP;

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

  Response: always HTTP 202.

.. _bug #1391866: https://bugs.launchpad.net/ironic-discoverd/+bug/1391866

Change Log
----------

v1.0.0
~~~~~~

* Discovery now times out by default.
* Add support for plugins that hook into data processing pipeline, see
  `plugin-architecture blueprint`_ for details.
* Cache nodes under discovery in a local SQLite database. Set ``database``
  configuration option to persist this database. Improves performance by
  making less calls to Ironic API.
* Create ``CONTRIBUTING.rst``.

.. _plugin-architecture blueprint: https://blueprints.launchpad.net/ironic-discoverd/+spec/plugin-architecture

v0.2.4
~~~~~~

* Urgent fix: add requirements.txt and tox.ini to the manifest.

v0.2.3
~~~~~~

* Moved to StackForge and LaunchPad.

v0.2.2
~~~~~~

* ``/v1/discover`` now does some sync sanity checks.
* On each start-up make several attempts to check that Ironic is available.
* Now we try a bit harder to recover firewall state on every step.
* ``discovery_timestamp`` is added to node extra on starting discovery
  (part of future fix for `bug #1391871`_).
* Actually able to start under Python 3.3 (still very experimental).
* Updated unit tests and this documentation.

.. _bug #1391871: https://bugs.launchpad.net/ironic-discoverd/+bug/1391871

v0.2.1
~~~~~~

* Expect ``interfaces`` instead of ``macs`` in post-back from the ramdisk.
* If ``interfaces`` is present, only add ports for NIC's with IP address set.
* Now MAC's are white-listed for all drivers, not only SSH; option
  ``ssh_driver_regex`` was dropped.
* Nodes will be always put into maintenance mode before discovery.

v0.2.0
~~~~~~

* Authentication via Keystone.
* Simple client in ``ironic_discoverd.client``.
* Switch to setuptools entry points.
* Switch to tox.
* Periodic firewall update is now configurable.
* SSH driver regex is now configurable.
* Supported on Python 3.3.
* Enhanced documentation.

v0.1.1
~~~~~~

* Added simple man page.
* Make interface configurable.

v0.1.0
~~~~~~

* First stable release.
