import re

from setuptools import setup


try:
    # Distributions have to delete *requirements.txt
    with open('requirements.txt', 'r') as fp:
        install_requires = [re.split(r'[<>=~]', line)[0]
                            for line in fp if line.strip()]
except EnvironmentError:
    print("No requirements.txt, not handling dependencies")
    install_requires = []


with open('ironic_inspector/__init__.py', 'rb') as fp:
    exec(fp.read())


setup(
    name = "ironic-inspector",
    version = __version__,
    description = open('README.rst', 'r').readline().strip(),
    author = "Dmitry Tantsur",
    author_email = "dtantsur@redhat.com",
    url = "https://pypi.python.org/pypi/ironic-discoverd",
    packages = ['ironic_inspector', 'ironic_inspector.plugins',
                'ironic_inspector.test', 'ironic_inspector.common',
                'ironic_inspector_ramdisk', 'ironic_inspector_ramdisk.test'],
    install_requires = install_requires,
    # because entry points don't work with multiple packages
    scripts = ['bin/ironic-inspector-ramdisk'],
    entry_points = {
        'console_scripts': [
            "ironic-inspector = ironic_inspector.main:main",
        ],
        'ironic_inspector.hooks.processing': [
            "scheduler = ironic_inspector.plugins.standard:SchedulerHook",
            "validate_interfaces = ironic_inspector.plugins.standard:ValidateInterfacesHook",
            "ramdisk_error = ironic_inspector.plugins.standard:RamdiskErrorHook",
            "example = ironic_inspector.plugins.example:ExampleProcessingHook",
            "extra_hardware = ironic_inspector.plugins.extra_hardware:ExtraHardwareHook",
            "root_device_hint = ironic_inspector.plugins.root_device_hint:RootDeviceHintHook",
        ],
        'openstack.cli.extension': [
            'baremetal-introspection = ironic_inspector.shell',
        ],
        'openstack.baremetal_introspection.v1': [
            "baremetal_introspection_start = ironic_inspector.shell:StartCommand",
            "baremetal_introspection_status = ironic_inspector.shell:StatusCommand",
        ],
        'oslo.config.opts': [
            "ironic_inspector = ironic_inspector.conf:list_opts",
            "ironic_inspector.common.swift = ironic_inspector.common.swift:list_opts"
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
