#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Install utility for package cloaked
"""

from os import path

from setuptools import setup

pkg_info = {}
with open(path.join(path.abspath(path.dirname(__file__)), 'cloak/pkg_info.py')) as version_file:
    exec(version_file.read(), pkg_info)
package_name = pkg_info['__package__']
package_version = pkg_info['__version__']

setup(
    author='Vikas Munshi',
    author_email='vikas.munshi@gmail.com',
    description='Python3 library for managing secrets',
    install_requires=['pyCryptoDome>=3.6.4', 'pyOpenSSL>=18.0.0'],
    license='GNU GPL3',
    long_description=open('README.md').read(),
    name=package_name,
    package_dir={package_name: package_name},
    packages=[package_name],
    platforms=['linux'],
    python_requires='>=3.6',
    url='https://github.com/vikasmunshi/secrets_management/',
    version=package_version,
)
