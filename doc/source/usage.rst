.. _usage:

Usage
=====

Refer to :ref:`api` for information on the HTTP API.
Refer to the `client page`_ for information on how to use CLI and Python
library.

.. _client page: https://pypi.python.org/pypi/python-ironic-inspector-client

Using from Ironic API
~~~~~~~~~~~~~~~~~~~~~

Ironic Kilo introduced support for hardware introspection under name of
"inspection". **ironic-inspector** introspection is supported for some generic
drivers, please refer to `Ironic inspection documentation`_ for details.

.. _Ironic inspection documentation: http://docs.openstack.org/developer/ironic/deploy/install-guide.html#hardware-inspection

.. _node_states:

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

.. _rules:

Introspection Rules
~~~~~~~~~~~~~~~~~~~

Inspector supports a simple JSON-based DSL to define rules to run during
introspection. Inspector provides an API to manage such rules, and will run
them automatically after running all processing hooks.

A rule consists of conditions to check, and actions to run. If conditions
evaluate to true on the introspection data, then actions are run on a node.

Available conditions and actions are defined by plugins, and can be extended,
see :ref:`contributing_link` for details. See :ref:`api` for specific calls
to define introspection rules.

Conditions
^^^^^^^^^^

A condition is represented by an object with fields:

``op`` the type of comparison operation, default available operators include:

* ``eq``, ``le``, ``ge``, ``ne``, ``lt``, ``gt`` - basic comparison operators;

* ``in-net`` - checks that an IP address is in a given network;

* ``matches`` - requires a full match against a given regular expression;

* ``contains`` - requires a value to contain a given regular expression;

* ``is-empty`` - checks that field is an empty string, list, dict or
  None value.

``field`` a `JSON path <http://goessner.net/articles/JsonPath/>`_ to the field
in the introspection data to use in comparison.

Starting with the Mitaka release, you can also apply conditions to ironic node
field. Prefix field with schema (``data://`` or ``node://``) to distinguish
between values from introspection data and node. Both schemes use JSON path::

    {'field': 'node://property.path', 'op': 'eq', 'value': 'val'}
    {'field': 'data://introspection.path', 'op': 'eq', 'value': 'val'}

if scheme (node or data) is missing, condition compares data with
introspection data.

``invert`` boolean value, whether to invert the result of the comparison.

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

Starting from Mitaka release, ``value`` field in actions supports fetching data
from introspection, it's using `python string formatting notation
<https://docs.python.org/2/library/string.html#formatspec>`_ ::

        {'action': 'set-attribute', 'path': '/driver_info/ipmi_address',
                   'value': '{data[inventory][bmc_address]}'}

.. _setting-ipmi-creds:

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

  Use ironic API version ``1.11`` (introduced in ironic 4.0.0),
  so that new node gets into ``enroll`` provision state::

    ironic --ironic-api-version 1.11 node-create -d <DRIVER> -i ipmi_address=<ADDRESS>

  Providing ``ipmi_address`` allows **ironic-inspector** to distinguish nodes.

* Start introspection with providing additional parameters:

  * ``new_ipmi_password`` IPMI password to set,
  * ``new_ipmi_username`` IPMI user name to set, defaults to one in node
    driver_info.

* Manually power on the nodes and wait.

* After introspection is finished (watch nodes power state or use
  **ironic-inspector** status API) you can move node to ``manageable`` and
  then ``available`` states - see `Node States`_.

Note that due to various limitations on password value in different BMC,
**ironic-inspector** will only accept passwords with length between 1 and 20
consisting only of letters and numbers.

.. _plugins:

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
    stores logs from ``logs`` field, see :ref:`api` for details.
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

Refer to :ref:`contributing_link` for information on how to write your
own plugin.

Discovery
~~~~~~~~~

Starting from Mitaka, **ironic-inspector** is able to register new nodes
in Ironic.

The existing ``node-not-found-hook`` handles what happens if
**ironic-inspector** receives inspection data from a node it can not identify.
This can happen if a node is manually booted without registering it with
Ironic first.

For discovery, the configuration file option ``node_not_found_hook`` should be
set to load the hook called ``enroll``. This hook will enroll the unidentified
node into Ironic using the ``fake`` driver (this driver is a configurable
option, set ``enroll_node_driver`` in the **ironic-inspector** configuration
file, to the Ironic driver you want).

The ``enroll`` hook will also set the ``ipmi_address`` property on the new
node, if its available in the introspection data we received,
see :ref:`ramdisk_callback`.

Once the ``enroll`` hook is finished, **ironic-inspector** will process the
introspection data in the same way it would for an identified node. It runs
the processing :ref:`plugins`, and after that it runs introspection
rules, which would allow for more customisable node configuration,
see :ref:`rules`.

A rule to set a node's Ironic driver to the ``agent_ipmitool`` driver and
populate the required driver_info for that driver would look like::

    "description": "Set IPMI driver_info if no credentials",
    "actions": [
        {'action': 'set-attribute', 'path': 'driver', 'value': 'agent_ipmitool'},
        {'action': 'set-attribute', 'path': 'driver_info/ipmi_username',
         'value': 'username'},
        {'action': 'set-attribute', 'path': 'driver_info/ipmi_password',
         'value': 'password'}
    ]
    "conditions": [
        {'op': 'is-empty', 'field': 'node://driver_info.ipmi_password'},
        {'op': 'is-empty', 'field': 'node://driver_info.ipmi_username'}
    ]

    "description": "Set deploy info if not already set on node",
    "actions": [
        {'action': 'set-attribute', 'path': 'driver_info/deploy_kernel',
         'value': '<glance uuid>'},
        {'action': 'set-attribute', 'path': 'driver_info/deploy_ramdisk',
         'value': '<glance uuid>'},
    ]
    "conditions": [
        {'op': 'is-empty', 'field': 'node://driver_info.deploy_ramdisk'},
        {'op': 'is-empty', 'field': 'node://driver_info.deploy_kernel'}
    ]

All nodes discovered and enrolled via the ``enroll`` hook, will contain an
``auto_discovered`` flag in the introspection data, this flag makes it
possible to distinguish between manually enrolled nodes and auto-discovered
nodes in the introspection rules using the rule condition ``eq``::

    "description": "Enroll auto-discovered nodes with fake driver",
    "actions": [
        {'action': 'set-attribute', 'path': 'driver', 'value': 'fake'}
    ]
    "conditions": [
        {'op': 'eq', 'field': 'data://auto_discovered', 'value': True}
    ]
