Hardware discovery for OpenStack Ironic
=======================================

.. image:: https://travis-ci.org/Divius/ironic-discoverd.svg?branch=master
    :target: https://travis-ci.org/Divius/ironic-discoverd

Running
-------

We're available on PyPI::

    pip install ironic-discoverd
    ironic-discoverd /path/to/conf

Or you can test locally::

    make test_env  # only the first time
    make test  # run tests
    .env/bin/python setup.py develop
    .env/bin/ironic-discoverd example.conf

Of course you may want to modify *example.conf* to match your OpenStack
environment.
