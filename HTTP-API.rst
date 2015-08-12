HTTP API
--------

By default **ironic-inspector** listens on ``0.0.0.0:5050``, port
can be changed in configuration. Protocol is JSON over HTTP.

Start Introspection
~~~~~~~~~~~~~~~~~~~

``POST /v1/introspection/<UUID>`` initiate hardware introspection for node
``<UUID>``. All power management configuration for this node needs to be done
prior to calling the endpoint (except when `Setting IPMI Credentials`_).

Requires X-Auth-Token header with Keystone token for authentication.

Optional parameters:

* ``new_ipmi_password`` if set, **ironic-inspector** will try to set IPMI
  password on the machine to this value. Power credentials validation will be
  skipped and manual power on will be required. See `Setting IPMI
  credentials`_ for details.

* ``new_ipmi_username`` provides new IPMI user name in addition to password
  set by ``new_ipmi_password``. Defaults to current ``ipmi_username`` in
  node ``driver_info`` field.

Response:

* 202 - accepted introspection request
* 400 - bad request
* 401, 403 - missing or invalid authentication
* 404 - node cannot be found

Get Introspection Status
~~~~~~~~~~~~~~~~~~~~~~~~

``GET /v1/introspection/<UUID>`` get hardware introspection status.

Requires X-Auth-Token header with Keystone token for authentication.

Response:

* 200 - OK
* 400 - bad request
* 401, 403 - missing or invalid authentication
* 404 - node cannot be found

Response body: JSON dictionary with keys:

* ``finished`` (boolean) whether introspection is finished
* ``error`` error string or ``null``

Ramdisk Callback
~~~~~~~~~~~~~~~~

``POST /v1/continue`` internal endpoint for the ramdisk to post back
discovered data. Should not be used for anything other than implementing
the ramdisk. Request body: JSON dictionary with at least these keys:

* ``cpus`` number of CPU
* ``cpu_arch`` architecture of the CPU
* ``memory_mb`` RAM in MiB
* ``local_gb`` hard drive size in GiB
* ``interfaces`` dictionary filled with data from all NIC's, keys being
  interface names, values being dictionaries with keys:

  * ``mac`` MAC address
  * ``ip`` IP address

* ``ipmi_address`` IP address of BMC, may be missing on VM
* ``boot_interface`` optional MAC address of the NIC that the machine
  PXE booted from either in standard format ``11:22:33:44:55:66`` or
  in *PXELinux* ``BOOTIF`` format ``01-11-22-33-44-55-66``.

* ``error`` optional error happened during ramdisk run, interpreted by
  ``ramdisk_error`` plugin

* ``logs`` optional base64-encoded logs from the ramdisk

* ``block_devices`` optional block devices information for
  ``root_device_hint`` plugin, dictionary with keys:

  * ``serials`` list of serial numbers of block devices.

.. note::
      This list highly depends on enabled plugins, provided above are
      expected keys for the default set of plugins. See Plugins_ for details.

.. note::
    This endpoint is not expected to be versioned, though versioning will work
    on it.

Response:

* 200 - OK
* 400 - bad request
* 403 - node is not on introspection
* 404 - node cannot be found or multiple nodes found

Response body: JSON dictionary. If `Setting IPMI Credentials`_ is requested,
body will contain the following keys:

* ``ipmi_setup_credentials`` boolean ``True``
* ``ipmi_username`` new IPMI user name
* ``ipmi_password`` new IPMI password

.. _Setting IPMI Credentials: https://github.com/openstack/ironic-inspector#setting-ipmi-credentials
.. _Plugins: https://github.com/openstack/ironic-inspector#plugins

Error Response
~~~~~~~~~~~~~~

If an error happens during request processing, **Ironic Inspector** returns
a response with an appropriate HTTP code set, e.g. 400 for bad request or
404 when something was not found (usually node in cache or node in ironic).
The following JSON body is returned::

    {
        "error": {
            "message": "Full error message"
        }
    }

This body may be extended in the future to include details that are more error
specific.

API Versioning
~~~~~~~~~~~~~~

The API supports optional API versioning. You can query for minimum and
maximum API version supported by the server. You can also declare required API
version in your requests, so that the server rejects request of unsupported
version.

.. note::
    Versioning was introduced in **Ironic Inspector 2.1.0**.

All versions must be supplied as string in form of ``X.Y``, where ``X`` is a
major version and is always ``1`` for now, ``Y`` is a minor version.

* If ``X-OpenStack-Ironic-Inspector-API-Version`` header is sent with request,
  the server will check if it supports this version. HTTP error 406 will be
  returned for unsupported API version.

* All HTTP responses contain
  ``X-OpenStack-Ironic-Inspector-API-Minimum-Version`` and
  ``X-OpenStack-Ironic-Inspector-API-Maximum-Version`` headers with minimum
  and maximum API versions supported by the server.

Version History
^^^^^^^^^^^^^^^

**1.0** version of API at the moment of introducing versioning.
