Hardware introspection for OpenStack Bare Metal
===============================================

This is an auxiliary service for discovering hardware properties for a
node managed by `Ironic`_. Hardware introspection or hardware
properties discovery is a process of getting hardware parameters required for
scheduling from a bare metal node, given it's power management credentials
(e.g. IPMI address, user name and password).

A special ramdisk is required to collect the information on a
node. The default one can be built using diskimage-builder_ and
`ironic-discoverd-ramdisk element`_ (see Configuration_ below).

* Free software: Apache license
* Source: http://git.openstack.org/cgit/openstack/ironic-inspector
* Bugs: http://bugs.launchpad.net/ironic-inspector
* Blueprints: https://blueprints.launchpad.net/ironic-inspector
* Downloads: https://pypi.python.org/pypi/ironic-inspector
* Python client library and CLI tool: `python-ironic-inspector-client
  <https://pypi.python.org/pypi/python-ironic-inspector-client>`_.

Refer to CONTRIBUTING.rst_ for instructions on how to contribute.

.. _Ironic: https://wiki.openstack.org/wiki/Ironic
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

* Operator enrolls nodes into Ironic_ e.g. via ironic CLI command.
  Power management credentials should be provided to Ironic at this step.

* Nodes are put in the correct state for introspection as described in
  `Node States`_.

* Operator sends nodes on introspection using **ironic-inspector** API or CLI
  (see Usage_).

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

* ``connection`` in the ``database`` section - SQLAlchemy connection string
  for the database;

* ``dnsmasq_interface`` - interface on which ``dnsmasq`` (or another DHCP
  service) listens for PXE boot requests (defaults to ``br-ctlplane`` which is
  a sane default for TripleO-based installations but is unlikely to work for
  other cases).

See comments inside `example.conf
<https://github.com/openstack/ironic-inspector/blob/master/example.conf>`_
for the other possible configuration options.

.. note::
    Configuration file contains a password and thus should be owned by ``root``
    and should have access rights like ``0600``.

**ironic-inspector** requires root rights for managing iptables. It gets them
by running ``ironic-inspector-rootwrap`` utility with ``sudo``.
To allow it, copy file ``rootwrap.conf`` and directory ``rootwrap.d`` to the
configuration directory (e.g. ``/etc/ironic-inspector/``) and create file
``/etc/sudoers.d/ironic-inspector-rootwrap`` with the following content::

   stack ALL=(root) NOPASSWD: /usr/bin/ironic-inspector-rootwrap /etc/ironic-inspector/rootwrap.conf *

.. DANGER::
   Be very careful about typos in ``/etc/sudoers.d/ironic-inspector-rootwrap``
   as any typo will break sudo for **ALL** users on the system. Especially,
   make sure there is a new line at the end of this file.

.. note::
    ``rootwrap.conf`` and all files in ``rootwrap.d`` must be writeable
    only by root.

.. note::
    If you store ``rootwrap.d`` in a different location, make sure to update
    the *filters_path* option in ``rootwrap.conf`` to reflect the change.

    If your ``rootwrap.conf`` is in a different location, then you need
    to update the *rootwrap_config* option in ``ironic-inspector.conf``
    to point to that location.

Replace ``stack`` with whatever user you'll be using to run
**ironic-inspector**.

Configuring PXE
^^^^^^^^^^^^^^^

As for PXE boot environment, you'll need:

* TFTP server running and accessible (see below for using *dnsmasq*).
  Ensure ``pxelinux.0`` is present in the TFTP root.


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

* You have to install and configure one of 2 available ramdisks: simple
  bash-based (see `Using simple ramdisk`_) or more complex based on
  ironic-python-agent_ (See `Using IPA`_).

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

Using simple ramdisk
^^^^^^^^^^^^^^^^^^^^

* Build and put into your TFTP the kernel and ramdisk created using the
  diskimage-builder_ `ironic-discoverd-ramdisk element`_::

    ramdisk-image-create -o discovery fedora ironic-discoverd-ramdisk

  You need diskimage-builder_ 0.1.38 or newer to do it (using the latest one
  is always advised).

* Configure your ``$TFTPROOT/pxelinux.cfg/default`` with something like::

    default introspect

    label introspect
    kernel discovery.kernel
    append initrd=discovery.initramfs discoverd_callback_url=http://{IP}:5050/v1/continue

    ipappend 3

  Replace ``{IP}`` with IP of the machine (do not use loopback interface, it
  will be accessed by ramdisk on a booting machine).

  .. note::
    There are some prebuilt images which use obsolete ``ironic_callback_url``
    instead of ``discoverd_callback_url``. Modify ``pxelinux.cfg/default``
    accordingly if you have one of these.

Using IPA
^^^^^^^^^

ironic-python-agent_ is a new ramdisk developed for Ironic. During the Liberty
cycle support for **ironic-inspector** was added. This is experimental
for now, but we plan on making IPA the default ramdisk in Mitaka cycle.

.. note::
    You need at least 1.5 GiB of RAM on the machines to use this ramdisk.

To build an ironic-python-agent ramdisk, do the following:

* Get the latest diskimage-builder_::

    sudo pip install -U "diskimage-builder>=1.1.2"

* Build the ramdisk::

    disk-image-create ironic-agent fedora -o ironic-agent

  .. note::
    Replace "fedora" with your distribution of choice.

* Copy resulting files ``ironic-agent.vmlinuz`` and ``ironic-agent.initramfs``
  to the TFTP root directory.

Next, set up ``$TFTPROOT/pxelinux.cfg/default`` as follows::

    default introspect

    label introspect
    kernel ironic-agent.vmlinuz
    append initrd=ironic-agent.initramfs ipa-inspection-callback-url=http://{IP}:5050/v1/continue systemd.journald.forward_to_console=yes

    ipappend 3

Replace ``{IP}`` with IP of the machine (do not use loopback interface, it
will be accessed by ramdisk on a booting machine).

.. note::
    While ``systemd.journald.forward_to_console=yes`` is not actually
    required, it will substantially simplify debugging if something goes wrong.

.. _diskimage-builder: https://github.com/openstack/diskimage-builder
.. _ironic-discoverd-ramdisk element: https://github.com/openstack/diskimage-builder/tree/master/elements/ironic-discoverd-ramdisk
.. _ironic-python-agent: https://github.com/openstack/ironic-python-agent

Managing the **ironic-inspector** database
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**ironic-inspector** provides a command line client for managing its database,
this client can be used for upgrading, and downgrading the database using
alembic migrations.

If this is your first time running **ironic-inspector** to migrate the
database simply run:
::

    ironic-inspector-dbsync --config-file /etc/ironic-inspector/inspector.conf upgrade

If you have previously run a version of **ironic-inspector** earlier than
2.2.0, the safest thing is to delete the existing SQLite database and run
``upgrade`` as shown above. If you, however, want to save the existing
database, to ensure your database will work with the migrations, you'll need to
run an extra step before upgrading the database. You only need to do this the
first time running version 2.2.0 or later.

If you are upgrading from **ironic-inspector** version 2.1.0 or lower:
::

    ironic-inspector-dbsync --config-file /etc/ironic-inspector/inspector.conf stamp --revision 578f84f38d
    ironic-inspector-dbsync --config-file /etc/ironic-inspector/inspector.conf upgrade

If you are upgrading from a git master install of **ironic-inspector** from
after `Introspection Rules`_ were introduced:
::

    ironic-inspector-dbsync --config-file /etc/ironic-inspector/inspector.conf stamp --revision d588418040d
    ironic-inspector-dbsync --config-file /etc/ironic-inspector/inspector.conf upgrade

Other available commands can be discovered by running::

    ironic-inspector-dbsync --help

Running
~~~~~~~

::

    ironic-inspector --config-file /etc/ironic-inspector/inspector.conf

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

* The nodes should be moved to ``MANAGEABLE`` provision state before
  introspection (requires *python-ironicclient* of version 0.5.0 or newer)::

    ironic node-set-provision-state <UUID> manage

* After successful introspection and before deploying nodes should be made
  available to Nova, by moving them to ``AVAILABLE`` state::

    ironic node-set-provision-state <UUID> provide

  .. note::
    Due to how Nova interacts with Ironic driver, you should wait 1 minute
    before Nova becomes aware of available nodes after issuing this command.
    Use ``nova hypervisor-stats`` command output to check it.

Introspection Rules
~~~~~~~~~~~~~~~~~~~

Inspector supports a simple JSON-based DSL to define rules to run during
introspection. Inspector provides an API to manage such rules, and will run
them automatically after running all processing hooks.

A rule consists of conditions to check, and actions to run. If conditions
evaluate to true on the introspection data, then actions are run on a node.
All actions have "rollback actions" associated with them, which are run when
conditions evaluate to false. This way we can safely rerun introspection.

Available conditions and actions are defined by plugins, and can be extended,
see CONTRIBUTING.rst_ for details. See `HTTP API`_ for specific calls to define
introspection rules.

Conditions
^^^^^^^^^^

A condition is represented by an object with fields:

``op`` the type of comparison operation, default available operators include :
``eq``, ``le``, ``ge``, ``ne``, ``lt``, ``gt`` (basic comparison operators),
``in-net`` (checks that IP address is in a given network).

``field`` a `JSON path <http://goessner.net/articles/JsonPath/>`_ to the field
in the introspection data to use in comparison.

``multiple`` how to treat situations where the ``field`` query returns multiple
results (e.g. the field contains a list), available options are:

* ``any`` (the default) require any to match,
* ``all`` require all to match,
* ``first`` requrie the first to match.

All other fields are passed to the condition plugin, e.g. numeric comparison
operations require a ``value`` field to compare against.

Actions
^^^^^^^

An action is represented by an object with fields:

``action`` type of action. Possible values are defined by plugins.

All other fields are passed to the action plugin.

Default available actions include:

* ``fail`` fail introspection. Requires a ``message`` parameter for the failure
  message.

* ``set-attribute`` sets an attribute on an Ironic node. Requires a ``path``
  field, which is the path to the attribute as used by ironic (e.g.
  ``/properties/something``), and a ``value`` to set.

* ``set-capability`` sets a capability on an Ironic node. Requires ``name``
  and ``value`` fields, which are the name and the value for a new capability
  accordingly. Existing value for this same capability is replaced.

* ``extend-attribute`` the same as ``set-attribute``, but treats existing
  value as a list and appends value to it. If optional ``unique`` parameter is
  set to ``True``, nothing will be added if given value is already in a list.

Setting IPMI Credentials
~~~~~~~~~~~~~~~~~~~~~~~~

If you have physical access to your nodes, you can use **ironic-inspector** to
set IPMI credentials for them without knowing the original ones. The workflow
is as follows:

* Ensure nodes will PXE boot on the right network by default.

* Set ``enable_setting_ipmi_credentials = true`` in the **ironic-inspector**
  configuration file, restart **ironic-inspector**.

* Enroll nodes in Ironic with setting their ``ipmi_address`` only (or
  equivalent driver-specific property, as per ``ipmi_address_fields``
  configuration option).

  With Ironic Liberty use ironic API version ``1.11``, so that new node gets
  into ``enroll`` provision state::

    ironic --ironic-api-version 1.11 node-create -d <DRIVER> -i ipmi_address=<ADDRESS>

  Providing ``ipmi_address`` allows **ironic-inspector** to distinguish nodes.

* With Ironic Kilo or older, set maintenance mode on nodes.
  That's an important step, otherwise Ironic might interfere with introspection
  process. This is replaced by ``enroll`` state in Ironic Liberty.

* Start introspection with providing additional parameters:

  * ``new_ipmi_password`` IPMI password to set,
  * ``new_ipmi_username`` IPMI user name to set, defaults to one in node
    driver_info.

* Manually power on the nodes and wait.

* After introspection is finished (watch nodes power state or use
  **ironic-inspector** status API) you can move node to ``manageable`` and
  then ``available`` states - see `Node States`_. With Ironic Kilo you have to
  move a node out of maintenance mode.

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
``raid_device`` (deprecated name ``root_device_hint``)
    gathers block devices from ramdisk and exposes root device in multiple
    runs.
``extra_hardware``
    stores the value of the 'data' key returned by the ramdisk as a JSON
    encoded string in a Swift object. The plugin will also attempt to convert
    the data into a format usable by introspection rules. If this is successful
    then the new format will be stored in the 'extra' key. The 'data' key is
    then deleted from the introspection data, as unless converted it's assumed
    unusable by introspection rules.

Refer to CONTRIBUTING.rst_ for information on how to write your own plugin.

Troubleshooting
---------------

Errors when starting introspection
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

* *Invalid provision state "available"*

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

Troubleshooting DNS issues on Ubuntu
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Ubuntu uses local DNS caching, so tries localhost for DNS results first
before calling out to an external DNS server. When DNSmasq is installed and
configured for use with ironic-inspector, it can cause problems by interfering
with the local DNS cache. To fix this issue ensure that ``/etc/resolve.conf``
points to your external DNS servers and not to ``127.0.0.1``.
