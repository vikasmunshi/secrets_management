#!/usr/bin/env python3
# -*- coding: utf-8 -*-
""" Update Version """

from os import path
from time import time

base_dirname = path.dirname(path.abspath(__file__))
major_version = 0
minor_version = 3
package_name = 'cloak'
package_version = '{}.{}.{}'.format(major_version, minor_version, int(time()) // 60)


def update_egg(filename: str) -> None:
    egg = '#egg={}-{}\n'.format(package_name, package_version)
    egg_identifier = '#egg={}-'.format(package_name)

    def update_egg_info(line: str) -> str:
        if egg_identifier in line:
            return ''.join(line.split('#')[:-1]) + egg
        return line

    with open(filename) as infile:
        file_contents = [update_egg_info(l) for l in infile.readlines()]
    with open(filename, 'w') as outfile:
        outfile.writelines(file_contents)


def update_version(filename: str, var_name: str) -> None:
    version_line = '{} = \'{}\'\n'.format(var_name, package_version)
    with open(filename) as infile:
        file_contents = [version_line if l.startswith(var_name) else l for l in infile.readlines()]
    with open(filename, 'w') as outfile:
        outfile.writelines(file_contents)


if __name__ == '__main__':
    for file_with_egg in (path.join(base_dirname, 'Dockerfile'), path.join(base_dirname, 'README.md')):
        update_egg(file_with_egg)

    for file_with_version, version_var_name in (
            (path.join(base_dirname, package_name, '__init__.py'), '__version__'),
            (path.join(base_dirname, package_name, 'tests', '__init__.py'), '__version__'),
            (path.join(base_dirname, 'setup.py'), 'package_version')):
        update_version(file_with_version, version_var_name)
