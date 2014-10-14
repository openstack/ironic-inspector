from setuptools import setup


setup(
    name = "ironic-discoverd",
    version = "0.2.1",
    description = "Hardware properties discovery for OpenStack Ironic",
    author = "Dmitry Tantsur",
    author_email = "dtansur@redhat.com",
    url = "https://github.com/Divius/ironic-discoverd/",
    packages = ['ironic_discoverd'],
    install_requires = ['Flask', 'python-ironicclient', 'eventlet',
                        'python-keystoneclient', 'requests', 'six'],
    entry_points = {'console_scripts': ["ironic-discoverd = ironic_discoverd.main:main"]},
)
