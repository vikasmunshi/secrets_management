#!/usr/bin/env python3
# -*- coding: utf-8 -*-
""" Update Version """

from os import path
from time import time

base_dirname = path.dirname(__file__)
package_name = 'cloak'
package_version = '0.2.' + str(int(time()))


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


def update_version(filename: str, version_line_identifier: str) -> None:
    version_line = '{} = \'{}\'\n'.format(version_line_identifier, package_version)
    with open(filename) as infile:
        file_contents = [version_line if l.startswith(version_line_identifier) else l for l in infile.readlines()]
    with open(filename, 'w') as outfile:
        outfile.writelines(file_contents)


if __name__ == '__main__':
    for file_with_egg in (path.join(base_dirname, 'Dockerfile'), path.join(base_dirname, 'README.md')):
        update_egg(file_with_egg)

    for file_with_version, identifier_text in (
            (path.join(base_dirname, package_name, '__init__.py'), '__version__'),
            (path.join(base_dirname, package_name, 'tests', '__init__.py'), '__version__'),
            (path.join(base_dirname, 'setup.py'), 'package_version')):
        update_version(file_with_version, identifier_text)
