.. _jobs-description:

================
Jobs description
================

The description of each jobs that runs in the CI when you submit a patch for
`openstack/ironic-inspector` is shown in the following table.

.. note::
    All jobs are configured to use a pre-build tinyipa ramdisk, a wholedisk
    image that is downloaded from a Swift temporary url, `pxe` boot and
    `ipmi` driver.


.. list-table:: Table. OpenStack Ironic Inspector CI jobs description
   :widths: 45 55
   :header-rows: 1

   * - Job name
     - Description
   * - ironic-inspector-grenade
     - Deploys Ironic and Ironic Inspector in DevStack and runs upgrade for
       all enabled services.
   * - ironic-inspector-tempest
     - Deploys Ironic and Ironic Inspector in DevStack.
       Runs tempest tests that match the regex `InspectorBasicTest` and
       deploys 1 virtual baremetal.
   * - ironic-inspector-tempest-discovery
     - Deploys Ironic and Ironic Inspector in DevStack.
       Runs tempest tests that match the regex `InspectorDiscoveryTest` and
       deploys 1 virtual baremetal.
   * - ironic-inspector-tempest-python3
     - Deploys Ironic and Ironic Inspector in DevStack under Python3.
       Runs tempest tests that match the regex `Inspector` and deploys 1
       virtual baremetal.
   * - openstack-tox-functional-py36
     - Run tox-based functional tests for Ironic Inspector under Python3.6
   * - bifrost-integration-tinyipa-ubuntu-xenial
     - Tests the integration between Ironic Inspector and Bifrost.
   * - ironic-inspector-tox-bandit
     - Runs bandit security tests in a tox environment to find known issues in
       the Ironic Inspector code.
