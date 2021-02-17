=======================
ironic-inspector-status
=======================

Synopsis
========

::

  ironic-inspector-status <category> <command> [<args>]

Description
===========

:program:`ironic-inspector-status` is a tool that provides routines for
checking the status of the ironic-inspector deployment.

Options
=======

The standard pattern for executing a :program:`ironic-inspector-status`
command is::

    ironic-inspector-status <category> <command> [<args>]

Run without arguments to see a list of available command categories::

    ironic-inspector-status

Categories are:

* ``upgrade``

Detailed descriptions are below.

You can also run with a category argument such as ``upgrade`` to see a list of
all commands in that category::

    ironic-inspector-status upgrade

These sections describe the available categories and arguments for
:program:`ironic-inspector-status`.

Upgrade
~~~~~~~

.. _ironic-inspector-status-checks:

``ironic-status upgrade check``
  Performs a release-specific readiness check before restarting services with
  new code. This command expects to have complete configuration and access
  to databases and services.

  **Return Codes**

  .. list-table::
     :widths: 20 80
     :header-rows: 1

     * - Return code
       - Description
     * - 0
       - All upgrade readiness checks passed successfully and there is nothing
         to do.
     * - 1
       - At least one check encountered an issue and requires further
         investigation. This is considered a warning but the upgrade may be OK.
     * - 2
       - There was an upgrade status check failure that needs to be
         investigated. This should be considered something that stops an
         upgrade.
     * - 255
       - An unexpected error occurred.

  **History of Checks**

  **Wallaby**

  * Adds initial status check command as it was not previously needed
    as the database structure and use of ironic-inspector's of
    ironic-inspector did not require the command previously.
  * Adds a check to validate the configured policy file is not JSON
    based as JSON based policies have been deprecated.
