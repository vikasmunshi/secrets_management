#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Install utility for package cloak
"""

from os import path

from setuptools import setup

package_name = 'cloak'
package_version = '0.1.7'

with open(path.join(path.dirname(__file__), 'requirements.txt')) as rf:
    package_requirements = rf.readlines()

version_line = '__version__ = \'{}\'\n'.format(package_version)
with open(path.join(path.dirname(__file__), package_name, 'version.py')) as vf:
    version_file = [version_line if l.startswith('__version__') else l for l in vf.readlines()]
with open(path.join(path.dirname(__file__), package_name, 'version.py'), 'w') as vf:
    vf.writelines(version_file)

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
    name=package_name,
    package_dir={package_name: package_name},
    packages=[package_name],
    platforms=['Linux', 'MacOS'],
    python_requires='>=3.6',
    url='https://github.com/vikasmunshi/secrets_management/',
    version=package_version,
)
