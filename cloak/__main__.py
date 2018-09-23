#!/usr/bin/env python3
# -*- coding: utf-8 -*-
""" Version Info """
import cloak


def generate_new_template(filename: str) -> None:
    from dataclasses import asdict
    from json import dump
    from collections import OrderedDict
    policy = OrderedDict({
        'subject': tuple((attrib, '') for attrib in cloak.subject_attribute_names),
        'subject_alt_names': (),
        'key_usage': asdict(cloak.KeyUsage()),
        'basic_constraints': asdict(cloak.BasicConstraints()),
        'key_size': 2048,
        'hash_algorithm': 'SHA256'
    })
    with open(filename, 'w') as outfile:
        dump(policy, outfile, indent=2)
    print('empty policy saved to {}'.format(filename))


def normalize_template(filename: str) -> None:
    try:
        policy = cloak.Policy.from_file(filename=filename)
    except AssertionError as e_policy:
        print('error in policy:\n{}'.format(e_policy))
    else:
        try:
            cloak.new_certificate_signing_request(policy=policy, rsa_key=cloak.new_rsa_key())
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
    \tpython -m {0} template [filename]\tgenerate empty csr policy file, default filename is template.json
    \tpython -m {0} normalize [filename]\tvalidate and normalize csr policy, default filename is template.json
    \tpython -m {0} csr [policy_file]\tgenerate rsa key and csr, default policy filename is template.json
    \t\t\t\t\t\tgenerated key and csr are saved as files with same name as policy and extensions .csr and .key
    """.strip().format(__package__)
    if len(argv) == 1:
        print('{} version {}'.format(cloak.__package__, cloak.__version__))
        print(usage)
    elif 'template'.startswith(argv[1].lower()):
        generate_new_template(argv[2] if len(argv) > 2 else 'template.json')
    elif 'normalize'.startswith(argv[1].lower()):
        normalize_template(argv[2] if len(argv) > 2 else 'template.json')
    elif 'csr' == argv[1] and len(argv) == 3:
        from os.path import splitext

        policy_file = argv[2]
        key_file = splitext(policy_file)[0] + '.key'
        csr_file = splitext(policy_file)[0] + '.csr'
        cloak.certificate_signing_request_main(policy_file, key_file, csr_file)
    else:
        print(usage)
