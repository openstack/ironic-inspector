Hardware introspection for OpenStack Bare Metal
===============================================

This is an auxiliary service for discovering hardware properties for a
node managed by `Ironic`_. Hardware introspection or hardware
properties discovery is a process of getting hardware parameters required for
scheduling from a bare metal node, given it's power management credentials
(e.g. IPMI address, user name and password).

A special ramdisk is required to collect the information on a
node. The default one can be built using diskimage-builder_ and
`ironic-discoverd-ramdisk element`_ (see :ref:`install_guide`).

* Free software: Apache license
* Source: http://git.openstack.org/cgit/openstack/ironic-inspector
* Bugs: http://bugs.launchpad.net/ironic-inspector
* Blueprints: https://blueprints.launchpad.net/ironic-inspector
* Downloads: https://pypi.python.org/pypi/ironic-inspector
* Python client library and CLI tool: `python-ironic-inspector-client
  <https://pypi.python.org/pypi/python-ironic-inspector-client>`_.

.. _Ironic: https://wiki.openstack.org/wiki/Ironic
.. _PyPI: https://pypi.python.org/pypi/ironic-inspector
.. _diskimage-builder: https://github.com/openstack/diskimage-builder
.. _ironic-discoverd-ramdisk element: https://github.com/openstack/diskimage-builder/tree/master/elements/ironic-discoverd-ramdisk

.. note::
    **ironic-inspector** was called *ironic-discoverd* before version 2.0.0.

For information on any current or prior version, see `the release
notes`_ and `the wiki pages`_.

.. _the release notes: releasenotes/index.html
.. _the wiki pages: https://wiki.openstack.org/wiki/Ironic/ReleaseNotes

Admin Guide
===========

Overview
--------

.. toctree::
  :maxdepth: 1

  Installation Guide <deploy/install-guide>
  Usage <usage/usage>
  Troubleshooting <troubleshooting/troubleshooting>

Developer Guide
===============

Introduction
------------

.. toctree::
  :maxdepth: 1

  Contribution Guide <dev/contributing_link>

API References
--------------

.. toctree::
  :maxdepth: 1

  HTTP API description <api/HTTP-API>

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
