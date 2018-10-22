.. -*- rst -*-

==========================
Process introspection data
==========================

After the ramdisk collects the required information from the bare metal
node, it should post it back to Inspector via ``POST /v1/continue`` method.


.. warning::
    Operators are reminded not to expose the Ironic Inspector API to
    unsecured networks. Below method is available to *unauthenticated*
    clients because **ironic-python-agent** ramdisk does not have access to
    keystone credentials.


Ramdisk Callback
================

.. rest_method::  POST /v1/continue

It is internal method for the ramdisk to post back all discovered data.
This should not be used for anything other than the ramdisk.

Full list of hardware inventory keys may be found in **ironic-python-agent**
documentation: `hardware inventory <https://docs.openstack.org/ironic-python-agent/latest/admin/how_it_works.html#hardware-inventory>`_.

Normal response codes: 201

Error codes: 400

Request
-------

List of mandatory hardware keys:

.. rest_parameters:: parameters.yaml

   - inventory: inventory
   - memory: memory
   - cpu: cpu
   - bmc_address: bmc_address
   - interfaces: interfaces
   - disks: disks
   - root_disk: root_disk
   - boot_interface: boot_interface
   - logs: logs

**Example node introspection continue request:**

.. literalinclude:: samples/api-v1-continue-request.json
   :language: javascript


Response
--------

The response will contain Ironic node ``uuid`` record.

.. rest_parameters:: parameters.yaml

    - uuid: node_uuid

**Example JSON representation:**

.. literalinclude:: samples/api-v1-common-node-uuid.json
   :language: javascript
