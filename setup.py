#!/usr/bin/env python3
# -*- coding: utf-8 -*-
""" Install utility for package cloak """

from os import path

from setuptools import find_packages, setup

package_name = 'cloak'
package_version = '0.3.25627594'

with open(path.join(path.dirname(__file__), 'requirements.txt')) as rf:
    package_requirements = rf.readlines()

setup(
    author='Vikas Munshi',
    author_email='vikas.munshi@gmail.com',
    classifiers=[
        'Programming Language :: Python :: 3.7',
        'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
        'Operating System :: POSIX :: Linux',
        'Operating System :: MacOS :: MacOS X',
    ],
    description='Python3 library for managing secrets',
    download_url='https://github.com/vikasmunshi/secrets_management/',
    install_requires=package_requirements,
    license='GNU GPL3',
    long_description=open('README.md').read(),
    name='{}-{}'.format(package_name, package_version),
    package_dir={package_name: package_name},
    packages=find_packages(),
    platforms=['Linux', 'MacOS'],
    python_requires='>=3.7',
    url='https://github.com/vikasmunshi/secrets_management/',
    version=package_version,
)
