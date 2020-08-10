:tocdepth: 2

============================
Bare Metal Introspection API
============================

By default **ironic-inspector** listens on ``[::]:5050``, host and port
can be changed in the configuration file. Protocol is JSON over HTTP.

.. rest_expand_all::

.. include:: introspection-api-versions.inc
.. include:: introspection-api-v1-introspection.inc
.. include:: introspection-api-v1-introspection-management.inc
.. include:: introspection-api-v1-continue.inc
.. include:: introspection-api-v1-rules.inc
