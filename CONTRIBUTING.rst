=================
How To Contribute
=================

Basics
~~~~~~

* Our source code is hosted on StackForge_ GitHub, but please do not send pull
  requests there.

* Please follow usual OpenStack `Gerrit Workflow`_ to submit a patch.

* Update change log in README.rst on any significant change.

* It goes without saying that any code change should by accompanied by unit
  tests.

* Note the branch you're proposing changes to. ``master`` is the current focus
  of development, use ``stable/VERSION`` for proposing an urgent fix, where
  ``VERSION`` is the current stable series. E.g. at the moment of writing the
  stable branch is ``stable/0.2``.

* Please file a launchpad_ blueprint for any significant code change and a bug
  for any significant bug fix.

.. _StackForge: https://github.com/stackforge/ironic-discoverd
.. _Gerrit Workflow: http://docs.openstack.org/infra/manual/developers.html#development-workflow
.. _launchpad: https://bugs.launchpad.net/ironic-discoverd

Development Environment
~~~~~~~~~~~~~~~~~~~~~~~

First of all, install *tox* utility. It's likely to be in your distribution
repositories under name of ``python-tox``. Alternatively, you can install it
from PyPI.

Next checkout and create environments::

    git clone https://github.com/stackforge/ironic-discoverd.git
    cd ironic-discoverd
    tox

Repeat *tox* command each time you need to run tests. If you don't have Python
interpreter of one of supported versions (currently 2.7 and 3.3), use
``-e`` flag to select only some environments, e.g.

::

    tox -e py27

.. note::
    Support for Python 3 is highly experimental, stay with Python 2 for the
    production environment for now.

There is a simple functional test that involves fetching the ramdisk from
Github::

    tox -e func

Run the service with::

    .tox/py27/bin/ironic-discoverd --config-file example.conf

Of course you may have to modify ``example.conf`` to match your OpenStack
environment.

Writing a Plugin
~~~~~~~~~~~~~~~~

**ironic-discoverd** allows to hook your code into data processing chain after
introspection. Inherit ``ProcessingHook`` class defined in
`ironic_discoverd.plugins.base
<https://github.com/stackforge/ironic-discoverd/blob/master/ironic_discoverd/plugins/base.py>`_
module and overwrite any or both of the following methods:

``before_processing(node_info)``
    called before any data processing, providing the raw data. Each plugin in
    the chain can modify the data, so order in which plugins are loaded
    matters here. Returns nothing.
``before_update(node,ports,node_info)``
    called after node is found and ports are created, but before data is
    updated on a node. Returns JSON patches for node and ports to apply.
    Please refer to the docstring for details and examples.
