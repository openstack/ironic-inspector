from setuptools import setup


setup(
    name = "ironic-discoverd",
    version = "0.0.1",
    author = "Dmitry Tantsur",
    author_email = "dtansur@redhat.com",
    packages=['ironic_discoverd'],
    install_requires = ['Flask', 'python-ironicclient'],
)
