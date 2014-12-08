import re

from setuptools import setup


with open('requirements.txt', 'r') as fp:
    install_requires = [re.split(r'[<>=]', line)[0]
                        for line in fp if line.strip()]


setup(
    name = "ironic-discoverd",
    version = "1.0.0",
    description = open('README.rst', 'r').readline().strip(),
    author = "Dmitry Tantsur",
    author_email = "dtantsur@redhat.com",
    url = "https://pypi.python.org/pypi/ironic-discoverd",
    packages = ['ironic_discoverd'],
    install_requires = install_requires,
    entry_points = {
        'console_scripts': [
            "ironic-discoverd = ironic_discoverd.main:main"
        ],
        'ironic_discoverd.hooks': [
            "scheduler = ironic_discoverd.plugins.standard:SchedulerHook",
            "validate_interfaces = ironic_discoverd.plugins.standard:ValidateInterfacesHook",
            "ramdisk_error = ironic_discoverd.plugins.standard:RamdiskErrorHook",
            "example = ironic_discoverd.plugins.example:ExampleProcessingHook",
        ],
    },
    classifiers = [
        'Development Status :: 5 - Production/Stable',
        'Environment :: OpenStack',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: Apache Software License',
        'Operating System :: POSIX',
    ],
    license = 'APL 2.0',
)
