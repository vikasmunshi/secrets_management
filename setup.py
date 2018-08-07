#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Install utility for package cloaked
"""

from setuptools import setup

setup(
    name='cloaked',
    version='0.0.1',
    author='Vikas Munshi',
    author_email='vikas.munshi@gmail.com',
    url='https://github.com/vikasmunshi/secrets_management/',
    description='Python3 library for managing secrets',
    packages=['cloaked'],
    package_dir={'cloaked': 'cloaked'},
    install_requires=['pycryptodome>=3.6.4'],
    license='GNU GPL3',
    platforms=['any'],
    long_description=open('README.md').read()
)
