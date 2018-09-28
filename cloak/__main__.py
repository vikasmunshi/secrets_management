#!/usr/bin/env python3
# -*- coding: utf-8 -*-
""" Version Info """
from os import path
from uuid import uuid4

import cloak


def generate_new_policy(filename: str) -> None:
    from dataclasses import asdict
    from json import dump
    from collections import OrderedDict
    policy = OrderedDict({
        'id': str(uuid4()),
        'url': 'https://raw.githubusercontent.com/vikasmunshi/secrets_management/master/policy/policy.json',
        'ra': 'https://localhost/',
        'subject': tuple((attrib, '') for attrib in cloak.subject_attribute_names),
        'subject_alt_names': (),
        'key_usage': asdict(cloak.KeyUsage()),
        'basic_constraints': asdict(cloak.BasicConstraints()),
        'key_size': 2048,
        'hash_algorithm': 'SHA256',
    })
    with open(filename, 'w') as outfile:
        dump(policy, outfile, indent=2)
    print('empty policy saved to {}'.format(filename))


def generate_new_template(filename: str) -> None:
    from dataclasses import asdict
    from json import dump
    from collections import OrderedDict
    template = OrderedDict({
        'id': str(uuid4()),
        'policy': 'https://raw.githubusercontent.com/vikasmunshi/secrets_management/master/policy/policy.json',
        'subject': tuple((attrib, '') for attrib in cloak.subject_attribute_names),
        'subject_alt_names': (),
        'key_usage': asdict(cloak.KeyUsage()),
        'basic_constraints': asdict(cloak.BasicConstraints()),
        'key_size': 2048,
        'hash_algorithm': 'SHA256',
        'key_store': 'key.json',
    })
    with open(filename, 'w') as outfile:
        dump(template, outfile, indent=2)
    print('empty template saved to {}'.format(filename))


def normalize_template(filename: str) -> None:
    try:
        policy = cloak.Template.from_file(filename=filename)
    except AssertionError as e_policy:
        print('error in policy:\n{}'.format(e_policy))
    else:
        try:
            cloak.new_certificate_signing_request(template=policy, rsa_key=cloak.new_rsa_key())
        except (AssertionError, ValueError) as e_csr:
            print('error in csr generation:\n{}'.format(e_csr))
        else:
            policy.to_file(filename)
            print('policy {} normalized'.format(filename))


if __name__ == '__main__':
    from sys import argv

    usage = """Usage:
    \tpython -m {0}\t\t\t\tprint package version and usage
    \tpython -m {0}.tests\t\t\trun package unit tests
    
    \tpython -m {0} template [filename]\tgenerate empty csr template file, default filename is template.json
    \tpython -m {0} normalize [filename]\tvalidate and normalize csr template, default filename is template.json
    
    \tpython -m {0} policy [filename]\tgenerate new ra policy file, default filename is policy.json
    
    \tpython -m {0} csr [policy_file]\tgenerate rsa key and csr, default template file is template.json
    \t\t\t\t\t\tgenerated key and csr are saved as files with same name as policy and extensions .csr and .key
    """.strip().format(__package__)
    if len(argv) == 1:
        print('{} version {}'.format(cloak.__package__, cloak.__version__))
        print(usage)
    elif 'template'.startswith(argv[1].lower()):
        generate_new_template(argv[2] if len(argv) > 2 else 'template.json')
    elif 'normalize'.startswith(argv[1].lower()):
        normalize_template(argv[2] if len(argv) > 2 else 'template.json')
    elif 'policy'.startswith(argv[1].lower()):
        generate_new_policy(argv[2] if len(argv) > 2 else 'policy.json')
    elif 'csr' == argv[1] and len(argv) == 3:
        template_file = argv[2]
        cloak.certificate_signing_request_main(template_file)
    else:
        print(usage)
