Hardware introspection for OpenStack Ironic
===========================================

This is an auxiliary service for discovering hardware properties for a
node managed by `OpenStack Ironic`_. Hardware introspection or hardware
properties discovery is a process of getting hardware parameters required for
scheduling from a bare metal node, given it's power management credentials
(e.g. IPMI address, user name and password).

A special ramdisk is required to collect the information on a
node. The default one can be built using diskimage-builder_ and
`ironic-discoverd-ramdisk element`_ (see Configuration_ below).

Support for **ironic-inspector** is present in `Tuskar UI`_ --
OpenStack Horizon plugin for TripleO_.

Please use launchpad_ to report bugs and ask questions. Use PyPI_ for
downloads and accessing the released version of this README. Refer to
CONTRIBUTING.rst_ for instructions on how to contribute.

.. _OpenStack Ironic: https://wiki.openstack.org/wiki/Ironic
.. _Tuskar UI: https://pypi.python.org/pypi/tuskar-ui
.. _TripleO: https://wiki.openstack.org/wiki/TripleO
.. _launchpad: https://bugs.launchpad.net/ironic-inspector
.. _PyPI: https://pypi.python.org/pypi/ironic-inspector
.. _CONTRIBUTING.rst: https://github.com/openstack/ironic-inspector/blob/master/CONTRIBUTING.rst

.. note::
    **ironic-inspector** was called *ironic-discoverd* before version 2.0.0.

Version Support Matrix
----------------------

**ironic-inspector** currently requires bare metal API version ``1.6`` to be
provided by Ironic. This version is available starting with Ironic Kilo
release.

Here is a mapping between Ironic versions and supported **ironic-inspector**
versions. The Standalone column shows which **ironic-inspector** versions can
be used in standalone mode with each Ironic version. The Inspection Interface
column shows which **ironic-inspector** versions can be used with the Ironic
inspection interface in each version of Ironic.

+--------------+-------------------------------+
|Ironic Version| Inspector (Discoverd) Version |
|              +----------+--------------------+
|              |Standalone|Inspection Interface|
+==============+==========+====================+
|Juno          |1.0       |N/A                 |
+--------------+----------+--------------------+
|Kilo          |1.0 - 2.2 |1.0 - 1.1           |
+--------------+----------+--------------------+
|Liberty       |1.1 - 2.X |2.0 - 2.X           |
+--------------+----------+--------------------+

.. note::
    ``2.X`` means we don't have specific plans on deprecating support for this
    Ironic version. This does not imply that we'll support it forever though.

Workflow
--------

Usual hardware introspection flow is as follows:

* Operator installs undercloud with **ironic-inspector**
  (e.g. using instack-undercloud_).

* Operator enrolls nodes into Ironic either manually or by uploading CSV file
  to `Tuskar UI`_. Power management credentials should be provided to Ironic
  at this step.

* Nodes are put in the correct state for introspection as described in
  `Node States`_.

* Operator sends nodes on introspection either manually using
  **ironic-inspector** API (see Usage_) or again via `Tuskar UI`_.

* On receiving node UUID **ironic-inspector**:

  * validates node power credentials, current power and provisioning states,
  * allows firewall access to PXE boot service for the nodes,
  * issues reboot command for the nodes, so that they boot the ramdisk.

* The ramdisk collects the required information and posts it back to
  **ironic-inspector**.

* On receiving data from the ramdisk, **ironic-inspector**:

  * validates received data,
  * finds the node in Ironic database using it's BMC address (MAC address in
    case of SSH driver),
  * fills missing node properties with received data and creates missing ports.

  .. note::
    **ironic-inspector** is responsible to create Ironic ports for some or all
    NIC's found on the node. **ironic-inspector** is also capable of
    deleting ports that should not be present. There are two important
    configuration options that affect this behavior: ``add_ports`` and
    ``keep_ports`` (please refer to ``example.conf`` for detailed explanation).

    Default values as of **ironic-inspector** 1.1.0 are ``add_ports=pxe``,
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

Install from PyPI_ (you may want to use virtualenv to isolate your
environment)::

    pip install ironic-inspector

Also there is a `DevStack <http://docs.openstack.org/developer/devstack/>`_
plugin for **ironic-inspector** - see CONTRIBUTING.rst_ for the current status.

Finally, some distributions (e.g. Fedora) provide **ironic-inspector**
packaged, some of them - under its old name *ironic-discoverd*.

Configuration
~~~~~~~~~~~~~

Copy ``example.conf`` to some permanent place
(e.g. ``/etc/ironic-inspector/inspector.conf``).
Fill in at least these configuration values:

* ``os_username``, ``os_password``, ``os_tenant_name`` - Keystone credentials
  to use when accessing other services and check client authentication tokens;

* ``os_auth_url``, ``identity_uri`` - Keystone endpoints for validating
  authentication tokens and checking user roles;

* ``database`` - where you want **ironic-inspector** SQLite database
  to be placed;

* ``dnsmasq_interface`` - interface on which ``dnsmasq`` (or another DHCP
  service) listens for PXE boot requests (defaults to ``br-ctlplane`` which is
  a sane default for TripleO_ based installations but is unlikely to work for
  other cases).

See comments inside `example.conf
<https://github.com/openstack/ironic-inspector/blob/master/example.conf>`_
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
  **ironic-inspector**. Don't do any firewall configuration:
  **ironic-inspector** will handle it for you. In **ironic-inspector**
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

Here is *inspector.conf* you may end up with::

    [DEFAULT]
    debug = false
    [ironic]
    identity_uri = http://127.0.0.1:35357
    os_auth_url = http://127.0.0.1:5000/v2.0
    os_username = admin
    os_password = password
    os_tenant_name = admin
    [firewall]
    dnsmasq_interface = br-ctlplane

.. note::
    Set ``debug = true`` if you want to see complete logs.

.. _diskimage-builder: https://github.com/openstack/diskimage-builder
.. _ironic-discoverd-ramdisk element: https://github.com/openstack/diskimage-builder/tree/master/elements/ironic-discoverd-ramdisk

Running
~~~~~~~

Run as ``root``::

    ironic-inspector --config-file /etc/ironic-inspector/inspector.conf

.. note::
    Running as ``root`` is not required if **ironic-inspector** does not
    manage the firewall (i.e. ``manage_firewall`` is set to ``false`` in the
    configuration file).

A good starting point for writing your own *systemd* unit should be `one used
in Fedora <http://pkgs.fedoraproject.org/cgit/openstack-ironic-discoverd.git/plain/openstack-ironic-discoverd.service>`_
(note usage of old name).

Usage
-----

Refer to HTTP-API.rst_ for information on the HTTP API.
Refer to the `client page`_ for information on how to use CLI and Python
library.

.. _HTTP-API.rst: https://github.com/openstack/ironic-inspector/blob/master/HTTP-API.rst
.. _HTTP API: https://github.com/openstack/ironic-inspector/blob/master/HTTP-API.rst
.. _client page: https://pypi.python.org/pypi/python-ironic-inspector-client

Using from Ironic API
~~~~~~~~~~~~~~~~~~~~~

Ironic Kilo introduced support for hardware introspection under name of
"inspection". **ironic-inspector** introspection is supported for some generic
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
    Due to how Nova interacts with Ironic driver, you should wait 1 minute
    before Nova becomes aware of available nodes after issuing these commands.

Setting IPMI Credentials
~~~~~~~~~~~~~~~~~~~~~~~~

If you have physical access to your nodes, you can use **ironic-inspector** to
set IPMI credentials for them without knowing the original ones. The workflow
is as follows:

* Ensure nodes will PXE boot on the right network by default.

* Set ``enable_setting_ipmi_credentials = true`` in the **ironic-inspector**
  configuration file.

* Enroll nodes in Ironic with setting their ``ipmi_address`` only. This step
  allows **ironic-inspector** to distinguish nodes.

* Set maintenance mode on nodes. That's an important step, otherwise Ironic
  might interfere with introspection process.

* Start introspection with providing additional parameters:

  * ``new_ipmi_password`` IPMI password to set,
  * ``new_ipmi_username`` IPMI user name to set, defaults to one in node
    driver_info.

* Manually power on the nodes and wait.

* After introspection is finished (watch nodes power state or use
  **ironic-inspector** status API) you can turn maintenance mode off.

Note that due to various limitations on password value in different BMC,
**ironic-inspector** will only accept passwords with length between 1 and 20
consisting only of letters and numbers.

Plugins
~~~~~~~

**ironic-inspector** heavily relies on plugins for data processing. Even the
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
``extra_hardware``
    stores the value of the 'data' key returned by the ramdisk as a JSON
    encoded string in a Swift object.

Refer to CONTRIBUTING.rst_ for information on how to write your own plugin.

Troubleshooting
---------------

Errors when starting introspection
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

* *Refusing to introspect node <UUID> with provision state "available"
  and maintenance mode off*

  In Kilo release with *python-ironicclient* 0.5.0 or newer Ironic
  defaults to reporting provision state ``AVAILABLE`` for newly enrolled
  nodes.  **ironic-inspector** will refuse to conduct introspection in
  this state, as such nodes are supposed to be used by Nova for scheduling.
  See `Node States`_ for instructions on how to put nodes into
  the correct state.

Introspection times out
~~~~~~~~~~~~~~~~~~~~~~~

There may be 3 reasons why introspection can time out after some time
(defaulting to 60 minutes, altered by ``timeout`` configuration option):

#. Fatal failure in processing chain before node was found in the local cache.
   See `Troubleshooting data processing`_ for the hints.

#. Failure to load the ramdisk on the target node. See `Troubleshooting
   PXE boot`_ for the hints.

#. Failure during ramdisk run. See `Troubleshooting ramdisk run`_ for the
   hints.

Troubleshooting data processing
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
In this case **ironic-inspector** logs should give a good idea what went wrong.
E.g. for RDO or Fedora the following command will output the full log::

    sudo journalctl -u openstack-ironic-inspector

(use ``openstack-ironic-discoverd`` for version < 2.0.0).

.. note::
    Service name and specific command might be different for other Linux
    distributions (and for old version of **ironic-inspector**).

If ``ramdisk_error`` plugin is enabled and ``ramdisk_logs_dir`` configuration
option is set, **ironic-inspector** will store logs received from the ramdisk
to the ``ramdisk_logs_dir`` directory. This depends, however, on the ramdisk
implementation.

Troubleshooting PXE boot
^^^^^^^^^^^^^^^^^^^^^^^^

PXE booting most often becomes a problem for bare metal environments with
several physical networks. If the hardware vendor provides a remote console
(e.g. iDRAC for DELL), use it to connect to the machine and see what is going
on. You may need to restart introspection.

Another source of information is DHCP and TFTP server logs. Their location
depends on how the servers were installed and run. For RDO or Fedora use::

    $ sudo journalctl -u openstack-ironic-inspector-dnsmasq

(use ``openstack-ironic-discoverd-dnsmasq`` for version < 2.0.0).

The last resort is ``tcpdump`` utility. Use something like
::

    $ sudo tcpdump -i any port 67 or port 68 or port 69

to watch both DHCP and TFTP traffic going through your machine. Replace
``any`` with a specific network interface to check that DHCP and TFTP
requests really reach it.

If you see node not attempting PXE boot or attempting PXE boot on the wrong
network, reboot the machine into BIOS settings and make sure that only one
relevant NIC is allowed to PXE boot.

If you see node attempting PXE boot using the correct NIC but failing, make
sure that:

#. network switches configuration does not prevent PXE boot requests from
   propagating,

#. there is no additional firewall rules preventing access to port 67 on the
   machine where *ironic-inspector* and its DHCP server are installed.

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
