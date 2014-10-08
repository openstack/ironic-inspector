from setuptools import setup


setup(
    name = "ironic-discoverd",
    version = "0.1.1",
    description = "Simple hardware discovery for OpenStack Ironic",
    author = "Dmitry Tantsur",
    author_email = "dtansur@redhat.com",
    url = "https://github.com/Divius/ironic-discoverd/",
    packages=['ironic_discoverd'],
    install_requires = ['Flask', 'python-ironicclient', 'eventlet'],
    scripts = ['bin/ironic-discoverd'],
)
