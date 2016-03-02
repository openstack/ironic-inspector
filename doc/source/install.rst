.. _install_guide:

Installation
------------

Install from PyPI_ (you may want to use virtualenv to isolate your
environment)::

    pip install ironic-inspector

Also there is a `DevStack <http://docs.openstack.org/developer/devstack/>`_
plugin for **ironic-inspector** - see :ref:`contributing_link` for the current
status.

Finally, some distributions (e.g. Fedora) provide **ironic-inspector**
packaged, some of them - under its old name *ironic-discoverd*.

.. _PyPI: https://pypi.python.org/pypi/ironic-inspector

Note for Ubuntu users
  Please beware :ref:`possible DNS issues <ubuntu-dns>` when installing
  Ironic-Inspector on Ubuntu.

Version Support Matrix
~~~~~~~~~~~~~~~~~~~~~~

**ironic-inspector** currently requires bare metal API version ``1.11`` to be
provided by Ironic. This version is available starting with Ironic Liberty
release.

Here is a mapping between Ironic versions and supported **ironic-inspector**
versions. The Standalone column shows which **ironic-inspector** versions can
be used in standalone mode with each Ironic version. The Inspection Interface
column shows which **ironic-inspector** versions can be used with the Ironic
inspection interface in each version of Ironic.

============== ========== ====================
Ironic Version Standalone Inspection Interface
============== ========== ====================
Juno           1.0        N/A
Kilo           1.0 - 2.2  1.0 - 1.1
Liberty        1.1 - 2.X  2.0 - 2.X
============== ========== ====================

.. note::
    ``2.X`` means we don't have specific plans on deprecating support for this
    Ironic version. This does not imply that we'll support it forever though.

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
    dhcp-sequential-ip

  .. note::
    ``dhcp-sequential-ip`` is used because otherwise a lot of nodes booting
    simultaneously cause conflicts - the same IP address is suggested to
    several nodes.

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

Using IPA
^^^^^^^^^

ironic-python-agent_ is a ramdisk developed for Ironic. During the Liberty
cycle support for **ironic-inspector** was added. This is the default ramdisk
starting with the Mitaka release.

.. note::
    You need at least 1.5 GiB of RAM on the machines to use this ramdisk,
    2 GiB is recommended.

To build an ironic-python-agent ramdisk, do the following:

* Get the new enough version of diskimage-builder_::

    sudo pip install -U "diskimage-builder>=1.1.2"

* Build the ramdisk::

    disk-image-create ironic-agent fedora -o ironic-agent

  .. note::
    Replace "fedora" with your distribution of choice.

* Copy resulting files ``ironic-agent.vmlinuz`` and ``ironic-agent.initramfs``
  to the TFTP root directory.

Alternatively, you can download a `prebuilt IPA image
<http://tarballs.openstack.org/ironic-python-agent/coreos/files/>`_ or use
the `CoreOS-based IPA builder
<http://docs.openstack.org/developer/ironic-python-agent/#coreos>`_.

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

This ramdisk is pluggable: you can insert introspection plugins called
*collectors* into it. For example, to enable a very handy ``logs`` collector
(sending ramdisk logs to **ironic-inspector**), modify the ``append`` line in
``$TFTPROOT/pxelinux.cfg/default``::

    append initrd=ironic-agent.initramfs ipa-inspection-callback-url=http://{IP}:5050/v1/continue ipa-inspection-collectors=default,logs systemd.journald.forward_to_console=yes

.. note::
    You probably want to always keep ``default`` collector, as it provides the
    basic information required for introspection.

.. _diskimage-builder: https://github.com/openstack/diskimage-builder
.. _ironic-python-agent: https://github.com/openstack/ironic-python-agent

Using simple ramdisk
^^^^^^^^^^^^^^^^^^^^

This ramdisk is deprecated, its use is not recommended.

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

.. _ironic-discoverd-ramdisk element: https://github.com/openstack/diskimage-builder/tree/master/elements/ironic-discoverd-ramdisk

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
after :ref:`rules` were introduced:
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
