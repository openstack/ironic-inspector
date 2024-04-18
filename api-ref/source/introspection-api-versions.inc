.. -*- rst -*-

============
API versions
============

Concepts
========

In order to bring new features to users over time, the Ironic
Inspector API supports versioning. There are two kinds of versions:

- ``major versions``, which have dedicated urls.
- ``microversions``, which can be requested through the use of the
  ``X-OpenStack-Ironic-Inspector-API-Version`` header or
  the new standard singular header
  ``OpenStack-API-Version: baremetal-introspection <version>``.

The Version APIs work differently from other APIs as they *do not* require
authentication.

All API requests support the new standard singular header
``OpenStack-API-Version: baremetal-introspection <version>`` and the legacy
``X-OpenStack-Ironic-Inspector-API-Version`` header.

Either of these headers SHOULD be supplied with every request; in the absence
of both headers, server will default to current supported version in all
responses.

List API versions
=================

.. rest_method::  GET /

This fetches all the information about all known major API versions in the
deployment. Links to more specific information will be provided for each major
API version, as well as information about supported min and max microversions.

Normal response codes: 200

Request
-------

Response Example
----------------

.. rest_parameters::  parameters.yaml

    - versions: versions
    - id: id
    - links: links
    - status: status

    - x-openstack-ironic-inspector-api-min-version: api-minimum-version
    - x-openstack-ironic-inspector-api-max-version: api-maximum-version

.. literalinclude:: samples/api-root-response.json
   :language: javascript


Show v1 API
===========

.. rest_method::  GET /v1/

Show all the resources within the Ironic Inspector v1 API.

Normal response codes: 200

Request
-------

Response Example
----------------

.. rest_parameters::  parameters.yaml

    - resources: resources
    - links: links
    - href: href
    - rel: rel
    - name: name

    - x-openstack-ironic-inspector-api-min-version: api-minimum-version
    - x-openstack-ironic-inspector-api-max-version: api-maximum-version

.. literalinclude:: samples/api-v1-root-response.json
   :language: javascript

Version History
===============

* **1.0** version of API at the moment of introducing versioning.
* **1.1** adds endpoint to retrieve stored introspection data.
* **1.2** endpoints for manipulating introspection rules.
* **1.3** endpoint for canceling running introspection.
* **1.4** endpoint for reapplying the introspection over stored data.
* **1.5** support for Ironic node names.
* **1.6** endpoint for rules creating returns 201 instead of 200 on success.
* **1.7** UUID, ``started_at``, ``finished_at`` in the introspection
  status API.
* **1.8** support for listing all introspection statuses.
* **1.9** de-activate setting IPMI credentials, if IPMI credentials
  are requested, API gets HTTP 400 response.
* **1.10** adds node state to the ``GET /v1/introspection/<node>`` and
  ``GET /v1/introspection`` API response data.
* **1.11** adds ``invert`` and multiple fields into rules response data.
* **1.12** this version indicates that support for setting IPMI credentials
  was completely removed from API (all versions).
* **1.13** adds ``manage_boot`` parameter for the introspection API.
* **1.14** allows formatting to be applied to strings nested in dicts and lists
  in the actions of introspection rules.
* **1.15** allows reapply with provided introspection data from request.
* **1.16** adds ``scope`` field to introspection rule.
* **1.17** adds ``GET /v1/introspection/<node>/data/unprocessed``.
* **1.18** adds state selector ``GET /v1/introspection?state=starting,...``.
