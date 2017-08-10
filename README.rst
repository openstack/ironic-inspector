===============================================
Hardware introspection for OpenStack Bare Metal
===============================================

Introduction
============

.. image:: http://governance.openstack.org/badges/ironic-inspector.svg
    :target: http://governance.openstack.org/reference/tags/index.html

This is an auxiliary service for discovering hardware properties for a
node managed by `Ironic`_. Hardware introspection or hardware
properties discovery is a process of getting hardware parameters required for
scheduling from a bare metal node, given it's power management credentials
(e.g. IPMI address, user name and password).

* Free software: Apache license
* Source: http://git.openstack.org/cgit/openstack/ironic-inspector
* Bugs: http://bugs.launchpad.net/ironic-inspector
* Downloads: https://pypi.python.org/pypi/ironic-inspector
* Documentation: https://docs.openstack.org/ironic-inspector/latest/
* Python client library and CLI tool: `python-ironic-inspector-client
  <https://pypi.python.org/pypi/python-ironic-inspector-client>`_
  (`documentation
  <https://docs.openstack.org/python-ironic-inspector-client/latest/>`_).

.. _Ironic: https://wiki.openstack.org/wiki/Ironic

.. note::
    **ironic-inspector** was called *ironic-discoverd* before version 2.0.0.

Release Notes
=============

For information on any current or prior version, see `the release notes`_.

.. _the release notes: http://docs.openstack.org/releasenotes/ironic-inspector/
