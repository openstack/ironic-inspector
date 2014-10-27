Hardware properties discovery for OpenStack Ironic
==================================================

.. image:: https://travis-ci.org/Divius/ironic-discoverd.svg?branch=master
    :target: https://travis-ci.org/Divius/ironic-discoverd

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

.. _OpenStack Ironic: https://wiki.openstack.org/wiki/Ironic
.. _Tuskar UI: https://pypi.python.org/pypi/tuskar-ui
.. _TripleO: https://wiki.openstack.org/wiki/TripleO
.. _instack-undercloud: https://openstack.redhat.com/Deploying_an_RDO_Undercloud_with_Instack

Installation
------------

*ironic-discoverd* is available as an RPM from Fedora 22 repositories or from
Juno RDO_ for Fedora 20, 21 and EPEL 7. It will be installed and preconfigured
if you used instack-undercloud_ to build your undercloud.
Otherwise after enabling required repositories install it using::

    yum install openstack-ironic-discoverd

and proceed with `Configuration`_.

Alternatively, you can install package from PyPI (you may want to use
virtualenv to isolate your environment)::

    pip install ironic-discoverd

.. _RDO: https://openstack.redhat.com/

Configuration
~~~~~~~~~~~~~

Copy ``example.conf`` to some permanent place
(``/etc/ironic-discoverd/discoverd.conf`` is what is used in the RPM).
You have to fill in configuration values with names starting with *os_*.
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

Developing
~~~~~~~~~~

First of all, install *tox* utility. It's likely to be in your distribution
repositories under name of ``python-tox``. Alternatively, you can install it
from PyPI.

Next checkout and create environments::

    git clone https://github.com/Divius/ironic-discoverd.git
    cd ironic-discoverd
    tox

Repeat *tox* command each time you need to run tests. If you don't have Python
interpreter of one of supported versions (currently 2.7 and 3.3), use
``-e`` flag to select only some environments, e.g.

::

    tox -e py27

.. note::
    Support for Python 3 is highly experimental, stay with Python 2 for the
    production environment for now.

Run like::

    .tox/py27/bin/ironic-discoverd example.conf

Of course you may have to modify ``example.conf`` to match your OpenStack
environment.

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
      but check for admin role is not implemented yet - see `bug #1`_.

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

.. _bug #1: https://github.com/Divius/ironic-discoverd/issues/1

Known Issues
------------

* `#4`_: Discovery never times out.

.. _#4: https://github.com/Divius/ironic-discoverd/issues/4

Change Log
----------

v0.2.2
~~~~~~

* ``/v1/discover`` now does some sync checks (`bug #3`_).
* Actually able to start under Python 3.3.
* On each start-up make several attempts to check that Ironic is available.
* Updated unit tests and this documentation.

.. _bug #3: https://github.com/Divius/ironic-discoverd/issues/3

v0.2.1
~~~~~~

* Expect ``interfaces`` instead of ``macs`` in post-back from the ramdisk
  (`bug #8`_).
* If ``interfaces`` is present, only add ports for NIC's with IP address set
  (also `bug #8`_).
* Now MAC's are white-listed for all drivers, not only SSH; option
  ``ssh_driver_regex`` was dropped (`bug #6`_).
* Nodes will be always put into maintenance mode before discovery (`bug #5`_).

.. _bug #8: https://github.com/Divius/ironic-discoverd/issues/8
.. _bug #6: https://github.com/Divius/ironic-discoverd/issues/6
.. _bug #5: https://github.com/Divius/ironic-discoverd/issues/5

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
