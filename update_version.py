#!/usr/bin/env python3
# -*- coding: utf-8 -*-
""" Update Version """

from os import path

package_name = 'cloak'
package_version = '0.2.2'


def update_version(filename: str, version_line_identifier: str) -> None:
    version_line = '{} = \'{}\'\n'.format(version_line_identifier, package_version)
    with open(filename) as infile:
        file_contents = [version_line if l.startswith(version_line_identifier) else l for l in infile.readlines()]
    with open(filename, 'w') as outfile:
        outfile.writelines(file_contents)


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


for fn in (path.join(path.dirname(__file__), package_name, '__init__.py'),
           path.join(path.dirname(__file__), package_name, 'tests', '__init__.py')):
    update_version(fn, '__version__')

update_version(path.join(path.dirname(__file__), 'setup.py'), 'package_version')
update_egg(path.join(path.dirname(__file__), 'Dockerfile'))
