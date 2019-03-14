.. -*- rst -*-

========================================
Introspection Management (introspection)
========================================

Abort introspection, get introspection data and reapply introspection can be
done through introspection sub-resources.

Abort Introspection
===================

.. rest_method::  POST /v1/introspection/{node_id}/abort

Abort running introspection.

Normal response codes: 202

Error codes:

* 400 - bad request
* 401, 403 - missing or invalid authentication
* 404 - node cannot be found
* 409 - inspector has locked this node for processing

Request
-------

.. rest_parameters:: parameters.yaml

   - node_id: node_id


Get Introspection data
======================

.. rest_method::  GET /v1/introspection/{node_id}/data

Return stored data from successful introspection.

.. note::
    We do not provide any backward compatibility guarantees regarding the
    format and contents of the stored data. Notably, it depends on the ramdisk
    used and plugins enabled both in the ramdisk and in inspector itself.

Normal response codes: 200

Error codes:

* 400 - bad request
* 401, 403 - missing or invalid authentication
* 404 - data cannot be found or data storage not configured

Request
-------

.. rest_parameters:: parameters.yaml

   - node_id: node_id


Response
--------

The response will contain introspection data in the form of json string.

**Example JSON representation of an introspection data:**

.. literalinclude:: samples/api-v1-data-introspection-response.json
   :language: javascript


Reapply Introspection on stored data
====================================

.. rest_method::  POST /v1/introspection/{node_id}/data/unprocessed

This method triggers introspection on stored unprocessed data.
No data is allowed to be sent along with the request.

.. note::

    Requires enabling introspection storage backend via ``[processing]store_data``.

Normal response codes: 202

Error codes:

* 400 - bad request or store not configured
* 401, 403 - missing or invalid authentication
* 404 - node not found for Node ID
* 409 - inspector locked node for processing


Request
-------

.. rest_parameters:: parameters.yaml

  - node_id: node_id
