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

* Nodes are put in the correct state for introspection as described in
  `Node States`_.

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

  .. note::
    **ironic-discoverd** is responsible to create Ironic ports for some or all
    NIC's found on the node. **ironic-discoverd** is also capable of
    deleting ports that should not be present. There are two important
    configuration options that affect this behavior: ``add_ports`` and
    ``keep_ports`` (please refer to ``example.conf`` for detailed explanation).

    Default values as of **ironic-discoverd** 1.1.0 are ``add_ports=pxe``,
    ``keep_ports=all``, which means that only one port will be added, which is
    associated with NIC the ramdisk PXE booted from. No ports will be deleted.
    This setting ensures that deploying on introspected nodes will succeed
    despite `Ironic bug 1405131
    <https://bugs.launchpad.net/ironic/+bug/1405131>`_.

    Ironic inspection feature by default requires different settings:
    ``add_ports=all``, ``keep_ports=present``, which means that ports will be
    created for all detected NIC's, and all other ports will be deleted.
    Refer to the `Ironic inspection documentation`_ for details.

* Separate API (see Usage_) can be used to query introspection results
  for a given node.

* Nodes are put in the correct state for deploying as described in
  `Node States`_.

Starting DHCP server and configuring PXE boot environment is not part of this
package and should be done separately.

.. _instack-undercloud: https://www.rdoproject.org/Deploying_an_RDO_Undercloud_with_Instack
.. _Ironic inspection documentation: http://docs.openstack.org/developer/ironic/deploy/install-guide.html#hardware-inspection

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

Using from Ironic API
~~~~~~~~~~~~~~~~~~~~~

Ironic Kilo introduced support for hardware introspection under name of
"inspection". **ironic-discoverd** introspection is supported for some generic
drivers, please refer to `Ironic inspection documentation`_ for details.

Node States
~~~~~~~~~~~

* As of Ironic Kilo release the nodes should be moved to ``MANAGEABLE``
  provision state before introspection (requires *python-ironicclient*
  of version 0.5.0 or newer)::

    ironic node-set-provision-state <UUID> manage

  With Juno release and/or older *python-ironicclient* it's recommended
  to set maintenance mode, so that nodes are not taken by Nova for deploying::

    ironic node-update <UUID> replace maintenance=true

* After successful introspection and before deploying nodes should be made
  available to Nova, either by moving them to ``AVAILABLE`` state (Kilo)::

    ironic node-set-provision-state <UUID> provide

  or by removing maintenance mode (Juno and/or older client)::

    ironic node-update <UUID> replace maintenance=false

  .. note::
    Due to how Ironic Nova driver works, you should wait up to 1 minute before
    Nova becomes aware of available nodes after issuing these commands.

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
    reports error, if ``error`` field is set by the ramdisk, also optionally
    stores logs from ``logs`` field, see `HTTP API`_ for details.
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

Troubleshooting
---------------

Errors when starting introspection
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

``Refusing to introspect node <UUID> with provision state "available"
and maintenance mode off``

    In Kilo release with *python-ironicclient* 0.5.0 or newer Ironic
    defaults to reporting provision state ``AVAILABLE`` for newly enrolled
    nodes.  **ironic-discoverd** will refuse to conduct introspection in
    this state, as such nodes are supposed to be used by Nova for scheduling.
    See `Node States`_ for instructions on how to put nodes into
    the correct state.

Introspection times out
~~~~~~~~~~~~~~~~~~~~~~~

There may be 3 reasons why introspection can time out after some time
(defaulting to 30 minutes):

#. Fatal failure in processing chain before node was found in the local cache.
   See `Troubleshooting data processing`_ for the hints.

#. Failure to load discovery ramdisk on the target node. See `Troubleshooting
   PXE boot`_ for the hints.

#. Failure during ramdisk run. See `Troubleshooting ramdisk run`_ for the
   hints.

Troubleshooting data processing
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
In this case **ironic-discoverd** logs should give a good idea what went wrong.
E.g. for Red Hat systems the following command will output the full log::

    sudo journalctl -u openstack-ironic-discoverd

If ``ramdisk_error`` plugin is enabled and ``ramdisk_logs_dir`` configuration
option is set, **ironic-discoverd** will store logs received from the ramdisk
to the ``ramdisk_logs_dir`` directory. This depends, however, on the ramdisk
implementation.

Troubleshooting PXE boot
^^^^^^^^^^^^^^^^^^^^^^^^

PXE booting most often becomes a problem for bare metal environments with
several physical networks. If the hardware vendor provides a remote console
(e.g. iDRAC for DELL), use it to connect to the machine and see what is going
on. You may need to restart introspection.

If you see node not attempting PXE boot or attempting PXE boot on the wrong
network, reboot the machine into BIOS settings and make sure that only one
relevant NIC is allowed to PXE boot.

If you see node attempting PXE boot using the correct NIC but failing, make
sure that:

#. network switches configuration does not prevent PXE boot requests from
   propagating,

#. there is no additional firewall rules preventing access to port 67.

If you see node receiving DHCP address and then failing to get kernel and/or
ramdisk or to boot them, make sure that:

#. TFTP server is running and accessible (use ``tftp`` utility to verify),

#. no firewall rules prevent access to TFTP port,

#. DHCP server is correctly set to point to the TFTP server,

#. ``pxelinux.cfg/default`` within TFTP root contains correct reference to the
   kernel and ramdisk.

Troubleshooting ramdisk run
^^^^^^^^^^^^^^^^^^^^^^^^^^^

Connect to the remote console as described in `Troubleshooting PXE boot`_ to
see what is going on with the ramdisk. The ramdisk drops into emergency shell
on failure, which you can use to look around. There should be file called
``logs`` with the current ramdisk logs.
