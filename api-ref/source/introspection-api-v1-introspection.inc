.. -*- rst -*-

==================
Node Introspection
==================

Start, abort introspection, get introspection status, and get introspection
data are done through the ``/v1/introspection`` resource. There are also
several sub-resources, which allow further actions to be performed on
introspection.

Start Introspection
===================

.. rest_method::  POST /v1/introspection/{node_id}

Initiate hardware introspection for node {node_id} . All power management
configuration for this node needs to be done prior to calling the endpoint.

In the case of missing or invalid authentication, the response code will be
401 and 403 respectively.
If Inspector doesn't find node {node_id}, it will return 404.

Normal response codes: 202

Error codes: 400, 401, 403, 404


Request
-------

.. rest_parameters:: parameters.yaml

   - node_id: node_id
   - manage_boot: manage_boot


Response
--------

The response will be empty body.

Get Introspection status
========================

.. rest_method::  GET /v1/introspection/{node_id}

Get node introspection status.

In case missing or invalid authentication response code will be 401 and 403.
If Inspector don't find node {node_id}, it will return 404.

Normal response codes: 200

Error codes: 400, 401, 403, 404

Request
-------

.. rest_parameters:: parameters.yaml

   - node_id: node_id


Response
--------

The response will contain the complete introspection info, like
start, finish time, introspection state, errors if any.

.. rest_parameters:: parameters.yaml

   - error: error
   - finished: finished
   - finished_at: finished_at
   - links: links
   - started_at: started_at
   - state: state
   - uuid: node_id

**Example JSON representation of an introspection:**

.. literalinclude:: samples/api-v1-get-introspection-response.json
   :language: javascript


List All Introspection statuses
===============================

.. rest_method::  GET /v1/introspection/

Returned status list is sorted by the ``started_at, uuid`` attribute pair,
newer items first.

In case missing or invalid authentication response code will be 401 and 403.

Normal response codes: 200

Error codes: 400, 401, 403

Request
-------

Status list may be paginated with these query string fields:

.. rest_parameters:: parameters.yaml

   - marker: marker
   - limit: limit


Response
--------

The response will contain a list of status objects:

.. rest_parameters:: parameters.yaml

   - error: error
   - finished: finished
   - finished_at: finished_at
   - links:  links
   - started_at: started_at
   - state: state
   - uuid: node_id


**Example JSON representation of an introspection:**

.. literalinclude:: samples/api-v1-get-introspections-response.json
   :language: javascript


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
