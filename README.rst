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
.. _diskimage-builder: https://github.com/openstack/diskimage-builder
.. _ironic-discoverd-ramdisk element: https://github.com/openstack/diskimage-builder/tree/master/elements/ironic-discoverd-ramdisk
.. _Configuration: https://github.com/openstack/ironic-inspector/blob/master/doc/source/install-guide.rst

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
  :ref:`node_states`.

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
  :ref:`node_states`.

Starting DHCP server and configuring PXE boot environment is not part of this
package and should be done separately.

.. _instack-undercloud: https://www.rdoproject.org/Deploying_an_RDO_Undercloud_with_Instack
.. _Ironic inspection documentation: http://docs.openstack.org/developer/ironic/deploy/install-guide.html#hardware-inspection
.. _Usage: https://github.com/openstack/ironic-inspector/blob/master/doc/source/usage.rst

