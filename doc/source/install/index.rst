Install Guide
=============

Install from PyPI_ (you may want to use virtualenv to isolate your
environment)::

    pip install ironic-inspector

Also there is a :devstack-doc:`DevStack <>` plugin for **ironic-inspector** -
see :ref:`contributing_link` for the current status.

Finally, some distributions (e.g. Fedora) provide **ironic-inspector**
packaged, some of them - under its old name *ironic-discoverd*.

There are several projects you can use to set up **ironic-inspector** in
production. `puppet-ironic <https://git.openstack.org/cgit/openstack/puppet-ironic/>`_
provides Puppet manifests, while :bifrost-doc:`bifrost <>` provides an
Ansible-based standalone installer. Refer to Configuration_ if you plan on
installing **ironic-inspector** manually.

.. _PyPI: https://pypi.org/project/ironic-inspector

.. note::
    Please beware of :ref:`possible DNS issues <ubuntu-dns>` when installing
    **ironic-inspector** on Ubuntu.

Sample Configuration Files
--------------------------

To generate a sample configuration file, run the following command from the
top level of the code tree::

    tox -egenconfig

For a pre-generated sample configuration file, see
:doc:`/configuration/sample-config`.

To generate a sample policy file, run the following command from the
top level of the code tree::

    tox -egenpolicy

For a pre-generated sample configuration file, see
:doc:`/configuration/sample-policy`.

Installation options
--------------------

Starting with Train release, ironic-inspector can run in a non-standalone
mode, which means ironic-inspector API and ironic-inspector conductor are
separated services, they can be installed on the same host or different
hosts.

Following are some considerations when you run ironic-inspector in
non-standalone mode:

* Additional packages may be required depending on the tooz backend used in
  the installation. For example, ``etcd3gw`` is required if the backend driver
  is configured to use ``etcd3+http://``, ``pymemcache`` is required to use
  ``memcached://``. Some distributions may provide packages like
  ``python3-etcd3gw`` or ``python3-memcache``. Supported drivers are listed at
  :tooz-doc:`Tooz drivers <user/drivers.html>`.

* For ironic-inspector running in non-standalone mode, PXE configuration is
  only required on the node where ironic-inspector conductor service is
  deployed.

* Switch to a database backend other than sqlite.

Configuration
-------------

Copy the sample configuration files to some permanent place
(e.g. ``/etc/ironic-inspector/inspector.conf``).
Fill in these minimum configuration values:

* The ``standalone`` in the ``DEFAULT`` section - This determines whether
  ironic-inspector services are intended to be deployed separately.

* The ``keystone_authtoken`` section - credentials to use when checking user
  authentication.

* The ``ironic`` section - credentials to use when accessing **ironic**
  API. When **ironic** is deployed standalone with no authentication, specify
  the following::

   [ironic]
   auth_type=none

  When **ironic** is deployed standalone with HTTP Basic authentication, valid
  credentials are also required::

   [ironic]
   auth_type=http_basic
   username=myName
   password=myPassword

* ``connection`` in the ``database`` section - SQLAlchemy connection string
  for the database. By default ironic-inspector uses sqlite as the database
  backend, if you are running ironic-inspector in a non-standalone mode,
  please change to other database backends.

* ``dnsmasq_interface`` in the ``iptables`` section - interface on which
  ``dnsmasq`` (or another DHCP service) listens for PXE boot requests
  (defaults to ``br-ctlplane`` which is a sane default for **tripleo**-based
  installations but is unlikely to work for other cases).

* if you wish to use the ``dnsmasq`` PXE/DHCP filter driver rather than the
  default ``iptables`` driver, see the :ref:`dnsmasq_pxe_filter` description.

* ``store_data`` in the ``processing`` section defines where introspection data
  is stored and takes one of three values:

  ``none``
    introspection data is not stored (the default)
  ``database``
    introspection data is stored in the database (recommended for standalone
    deployments)
  ``swift``
    introspection data is stored in the Object Store service (recommended for
    full openstack deployments)

  .. note::
    It is possible to create third party storage backends using the
    ``ironic_inspector.introspection_data.store`` entry point.

See comments inside :doc:`the sample configuration
</configuration/sample-config>` for other possible configuration options.

.. note::
    Configuration file contains a password and thus should be owned by ``root``
    and should have access rights like ``0600``.

Here is an example *inspector.conf* (adapted from a gate run)::

    [DEFAULT]
    debug = false
    rootwrap_config = /etc/ironic-inspector/rootwrap.conf

    [database]
    connection = mysql+pymysql://root:<PASSWORD>@127.0.0.1/ironic_inspector?charset=utf8

    [pxe_filter]
    driver=iptables

    [iptables]
    dnsmasq_interface = br-ctlplane

    [ironic]
    os_region = RegionOne
    project_name = service
    password = <PASSWORD>
    username = ironic-inspector
    auth_url = http://127.0.0.1/identity
    auth_type = password

    [keystone_authtoken]
    www_authenticate_uri = http://127.0.0.1/identity
    project_name = service
    password = <PASSWORD>
    username = ironic-inspector
    auth_url = http://127.0.0.1/identity_v2_admin
    auth_type = password

    [processing]
    ramdisk_logs_dir = /var/log/ironic-inspector/ramdisk
    store_data = swift

    [swift]
    os_region = RegionOne
    project_name = service
    password = <PASSWORD>
    username = ironic-inspector
    auth_url = http://127.0.0.1/identity
    auth_type = password

.. note::
    Set ``debug = true`` if you want to see complete logs.

**ironic-inspector** requires root rights for managing ``iptables``. It
gets them by running ``ironic-inspector-rootwrap`` utility with ``sudo``.
To allow it, copy file ``rootwrap.conf`` and directory ``rootwrap.d`` to the
configuration directory (e.g. ``/etc/ironic-inspector/``) and create file
``/etc/sudoers.d/ironic-inspector-rootwrap`` with the following content::

   Defaults:stack !requiretty
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

Configuring IPA
~~~~~~~~~~~~~~~

:ironic-python-agent-doc:`ironic-python-agent <>` is a ramdisk developed for
**ironic** and support for **ironic-inspector** was added during the Liberty
cycle. This is the default ramdisk starting with the Mitaka release.

.. note::
    You need at least 2 GiB of RAM on the machines to use IPA built with
    diskimage-builder_ and at least 384 MiB to use the *TinyIPA*.

To build an **ironic-python-agent** ramdisk, use ironic-python-agent-builder_.
Alternatively, you can download a `prebuild image
<https://tarballs.openstack.org/ironic-python-agent/dib/files/>`_.

For local testing and CI purposes you can use `a TinyIPA image
<https://tarballs.openstack.org/ironic-python-agent/tinyipa/files/>`_.

.. NOTE(dtantsur): both projects are branchless, using direct links
.. _ironic-python-agent-builder: https://docs.openstack.org/ironic-python-agent-builder/latest/admin/dib.html
.. _diskimage-builder: https://docs.openstack.org/diskimage-builder/latest/

Configuring PXE
~~~~~~~~~~~~~~~

For the PXE boot environment, you'll need:

* TFTP server running and accessible (see below for using *dnsmasq*).
  Ensure ``pxelinux.0`` is present in the TFTP root.

  Copy ``ironic-python-agent.kernel`` and ``ironic-python-agent.initramfs``
  to the TFTP root as well.

* Next, setup ``$TFTPROOT/pxelinux.cfg/default`` as follows::

    default introspect

    label introspect
    kernel ironic-python-agent.kernel
    append initrd=ironic-python-agent.initramfs ipa-inspection-callback-url=http://{IP}:5050/v1/continue systemd.journald.forward_to_console=yes

    ipappend 3

  Replace ``{IP}`` with IP of the machine (do not use loopback interface, it
  will be accessed by ramdisk on a booting machine).

  .. note::
     While ``systemd.journald.forward_to_console=yes`` is not actually
     required, it will substantially simplify debugging if something
     goes wrong. You can also enable IPA debug logging by appending
     ``ipa-debug=1``.

  IPA is pluggable: you can insert introspection plugins called
  *collectors* into it. For example, to enable a very handy ``logs`` collector
  (sending ramdisk logs to **ironic-inspector**), modify the ``append``
  line in ``$TFTPROOT/pxelinux.cfg/default``::

    append initrd=ironic-python-agent.initramfs ipa-inspection-callback-url=http://{IP}:5050/v1/continue ipa-inspection-collectors=default,logs systemd.journald.forward_to_console=yes

  .. note::
     You probably want to always keep the ``default`` collector, as it provides
     the basic information required for introspection.

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

Configuring iPXE
~~~~~~~~~~~~~~~~

iPXE allows better scaling as it primarily uses the HTTP protocol instead of
slow and unreliable TFTP. You still need a TFTP server as a fallback for
nodes not supporting iPXE. To use iPXE, you'll need:

* TFTP server running and accessible (see above for using *dnsmasq*).
  Ensure ``undionly.kpxe`` is present in the TFTP root. If any of your nodes
  boot with UEFI, you'll also need ``ipxe.efi`` there.

* You also need an HTTP server capable of serving static files.
  Copy ``ironic-python-agent.kernel`` and ``ironic-python-agent.initramfs``
  there.

* Create a file called ``inspector.ipxe`` in the HTTP root (you can name and
  place it differently, just don't forget to adjust the *dnsmasq.conf* example
  below)::

    #!ipxe

    :retry_dhcp
    dhcp || goto retry_dhcp

    :retry_boot
    imgfree
    kernel --timeout 30000 http://{IP}:8088/ironic-python-agent.kernel ipa-inspection-callback-url=http://{IP}>:5050/v1/continue systemd.journald.forward_to_console=yes BOOTIF=${mac} initrd=agent.ramdisk || goto retry_boot
    initrd --timeout 30000 http://{IP}:8088/ironic-python-agent.ramdisk || goto retry_boot
    boot

  .. note::
     Older versions of the iPXE ROM tend to misbehave on unreliable network
     connection, thus we use the timeout option with retries.

  Just like with PXE, you can customize the list of collectors by appending
  the ``ipa-inspection-collectors`` kernel option. For example::

    ipa-inspection-collectors=default,logs,extra_hardware

* Just as with PXE, you'll need a PXE boot server. The configuration, however,
  will be different. Here is an example *dnsmasq.conf*::

    port=0
    interface={INTERFACE}
    bind-interfaces
    dhcp-range={DHCP IP RANGE, e.g. 192.168.0.50,192.168.0.150}
    enable-tftp
    tftp-root={TFTP ROOT, e.g. /tftpboot}
    dhcp-sequential-ip
    dhcp-match=ipxe,175
    dhcp-match=set:efi,option:client-arch,7
    dhcp-match=set:efi,option:client-arch,9
    dhcp-match=set:efi,option:client-arch,11
    # dhcpv6.option: Client System Architecture Type (61)
    dhcp-match=set:efi6,option6:61,0007
    dhcp-match=set:efi6,option6:61,0009
    dhcp-match=set:efi6,option6:61,0011
    dhcp-userclass=set:ipxe6,iPXE
    # Client is already running iPXE; move to next stage of chainloading
    dhcp-boot=tag:ipxe,http://{IP}:8088/inspector.ipxe
    # Client is PXE booting over EFI without iPXE ROM,
    # send EFI version of iPXE chainloader
    dhcp-boot=tag:efi,tag:!ipxe,ipxe.efi
    dhcp-option=tag:efi6,tag:!ipxe6,option6:bootfile-url,tftp://{IP}/ipxe.efi
    # Client is running PXE over BIOS; send BIOS version of iPXE chainloader
    dhcp-boot=undionly.kpxe,localhost.localdomain,{IP}

  First, we configure the same common parameters as with PXE. Then we define
  ``ipxe`` and ``efi`` tags for IPv4 and ``ipxe6`` and ``efi6`` for IPv6.
  Nodes already supporting iPXE are ordered to download and execute
  ``inspector.ipxe``. Nodes without iPXE booted with UEFI will get ``ipxe.efi``
  firmware to execute, while the remaining will get ``undionly.kpxe``.

Configuring PXE for aarch64
~~~~~~~~~~~~~~~~~~~~~~~~~~~

For aarch64 Bare Metals, the PXE boot environment is basically the same as
x86_64, you'll need:

* TFTP server running and accessible (see below for using *dnsmasq*).
  Ensure ``grubaa64.efi`` is present in the TFTP root. The firmware can be
  retrieved from the installation distributions for aarch64.

* Copy ``ironic-agent.kernel`` and ``ironic-agent.initramfs`` to the TFTP root
  as well. Note that the ramdisk needs to be pre-built on an aarch64 machine
  with tools like ``ironic-python-agent-builder``, see
  https://docs.openstack.org/ironic-python-agent-builder/latest/admin/dib.html
  for how to build ramdisk for aarch64.

* Next, setup ``$TFTPROOT/EFI/BOOT/grub.cfg`` as follows::

    set default="1"
    set timeout=5

    menuentry 'Introspection for aarch64' {
        linux ironic-agent.kernel text showopts selinux=0 ipa-inspection-callback-url=http://{IP}:5050/v1/continue ipa-inspection-collectors=default ipa-collect-lldp=1 systemd.journald.forward_to_console=no
        initrd ironic-agent.initramfs
    }

  Replace ``{IP}`` with IP of the machine (do not use loopback interface, it
  will be accessed by ramdisk on a booting machine).

* Update DHCP options for aarch64, here is an example *dnsmasq.conf*::

    port=0
    interface={INTERFACE}
    bind-interfaces
    dhcp-range={DHCP IP RANGE, e.g. 192.168.0.50,192.168.0.150}
    enable-tftp
    dhcp-match=aarch64, option:client-arch, 11 # aarch64
    dhcp-boot=tag:aarch64, grubaa64.efi
    tftp-root={TFTP ROOT, e.g. /tftpboot}
    dhcp-sequential-ip


Configuring PXE for Multi-arch
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

If the environment consists of bare metals with different architectures,
normally different ramdisks are required for each architecture. The grub
built-in variable `grub_cpu`_ could be used to locate the correct config
file for each of them.

.. _grub_cpu: https://www.gnu.org/software/grub/manual/grub/html_node/grub_005fcpu.html

For example, setup ``$TFTPROOT/EFI/BOOT/grub.cfg`` as following::

    set default=master
    set timeout=5
    set hidden_timeout_quiet=false

    menuentry "master"  {
    configfile /tftpboot/grub-${grub_cpu}.cfg
    }

Prepare specific grub config for each existing architectures, e.g.
``grub-arm64.cfg`` for ARM64 and ``grub-x86_64.cfg`` for x86_64.

Update dnsmasq configuration to contain options for supported architectures.

Managing the **ironic-inspector** Database
------------------------------------------

**ironic-inspector** provides a command line client for managing its
database. This client can be used for upgrading, and downgrading the database
using `alembic <https://alembic.readthedocs.org/>`_ migrations.

If this is your first time running **ironic-inspector** to migrate the
database, simply run:
::

    ironic-inspector-dbsync --config-file /etc/ironic-inspector/inspector.conf upgrade

If you have previously run a version of **ironic-inspector** earlier than
2.2.0, the safest thing is to delete the existing SQLite database and run
``upgrade`` as shown above. However, if you want to save the existing
database, to ensure your database will work with the migrations, you'll need to
run an extra step before upgrading the database. You only need to do this the
first time running version 2.2.0 or later.

If you are upgrading from **ironic-inspector** version 2.1.0 or lower:
::

    ironic-inspector-dbsync --config-file /etc/ironic-inspector/inspector.conf stamp --revision 578f84f38d
    ironic-inspector-dbsync --config-file /etc/ironic-inspector/inspector.conf upgrade

If you are upgrading from a git master install of the **ironic-inspector**
after :ref:`rules <introspection_rules>` were introduced:
::

    ironic-inspector-dbsync --config-file /etc/ironic-inspector/inspector.conf stamp --revision d588418040d
    ironic-inspector-dbsync --config-file /etc/ironic-inspector/inspector.conf upgrade

Other available commands can be discovered by running::

    ironic-inspector-dbsync --help

Running
-------

Running in standalone mode
~~~~~~~~~~~~~~~~~~~~~~~~~~

Execute::

    ironic-inspector --config-file /etc/ironic-inspector/inspector.conf

Running in non-standalone mode
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

API service can be started in development mode with::

    ironic-inspector-api-wsgi -p 5050 -- --config-file /etc/ironic-inspector/inspector.conf

For production, the ironic-inspector API service should be hosted under a web
service. Below is a sample configuration for Apache with module mod_wsgi::

    Listen 5050

    <VirtualHost *:5050>
        WSGIDaemonProcess ironic-inspector user=stack group=stack threads=10 display-name=%{GROUP}
        WSGIScriptAlias / /usr/local/bin/ironic-inspector-api-wsgi

        SetEnv APACHE_RUN_USER stack
        SetEnv APACHE_RUN_GROUP stack
        WSGIProcessGroup ironic-inspector

        ErrorLog /var/log/apache2/ironic_inspector_error.log
        LogLevel info
        CustomLog /var/log/apache2/ironic_inspector_access.log combined

        <Directory /opt/stack/ironic-inspector/ironic_inspector/cmd>
            WSGIProcessGroup ironic-inspector
            WSGIApplicationGroup %{GLOBAL}
            AllowOverride All
            Require all granted
        </Directory>
    </VirtualHost>

You can refer to
:ironic-doc:`ironic installation document
<install/install-rdo.html#configuring-ironic-api-behind-mod-wsgi>`
for more guides.

ironic-inspector conductor can be started with::

    ironic-inspector-conductor --config-file /etc/ironic-inspector/inspector.conf
