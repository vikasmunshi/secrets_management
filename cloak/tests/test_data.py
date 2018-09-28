#!/usr/bin/env python3
# -*- coding: utf-8 -*-
""" test data for cloak.tests"""
import cloak

rsa_key = cloak.new_rsa_key()
rsa_pub_key = rsa_key.public_key()

rsa_keys = tuple(cloak.new_rsa_key() for _ in range(5))
rsa_pub_keys = tuple(key.public_key() for key in rsa_keys)
rsa_key_pairs = zip(rsa_keys, rsa_pub_keys)

random_strings = tuple(cloak.random_str(2 ** x) for x in range(9))

test_policies = (
    cloak.Template(
        subject=(
            ('commonName', 'test common name'),
            ('organizationName', 'test org'),
            ('organizationalUnitName', 'test ou'),
        ),
        subject_alt_names=('www.test.org', 'www.test.net'),
        key_usage=cloak.KeyUsage(digital_signature=True, key_encipherment=True),
        basic_constraints=cloak.BasicConstraints(ca=False)
    ),
    cloak.Template(
        subject=(
            ('commonName', 'test common name'),
            ('organizationName', 'test org'),
            ('organizationalUnitName', 'test ou 1'),
            ('organizationalUnitName', 'test ou 2'),
        ),
        subject_alt_names=('www.test.org', 'www.test.net'),
        key_usage=cloak.KeyUsage(digital_signature=True, key_encipherment=True)
    ),
)

valid_policy_dicts = (
    {
        'subject': (
            ('commonName', 'test common name'),
            ('organizationName', 'test org'),
            ('organizationalUnitName', 'test ou')
        ),
        'subject_alt_names': ('www.test.org', 'www.test.net'),
        'key_usage': {'digital_signature': True, 'key_encipherment': True},
        'basic_constraints': {'ca': False, 'path_length': None},
        'key_size': 2048,
        'hash_algorithm': 'SHA256'
    },
    {
        'subject': (
            ('commonName', 'test ca name'),
            ('organizationName', 'test org'),
            ('organizationalUnitName', 'test ou')
        ),
        'subject_alt_names': ('www.test.org', 'www.test.net'),
        'key_usage': {'digital_signature': True, 'key_encipherment': True},
        'basic_constraints': {'ca': True, 'path_length': 3},
        'key_size': 2048,
        'hash_algorithm': 'SHA256'
    },
    {
        'subject': (
            ('commonName', 'test common name'),
            ('organizationName', 'test org'),
            ('organizationalUnitName', 'test ou 1'),
            ('organizationalUnitName', 'test ou 2')
        ),
        'subject_alt_names': ('www.test.org', 'www.test.net'),
        'key_usage': {'digital_signature': True, 'key_encipherment': True}
    },
    {
        'subject': (
            ('commonName', 'test common name 3'),
            ('organizationName', 'test org'),
            ('organizationalUnitName', 'test ou 1'),
        ),
        'subject_alt_names': ('www.test.org', 'www.test.net'),
        'key_usage': {'key_agreement': True, 'encipher_only': True}
    },
)

invalid_policy_dicts = (
    {
        'subject': (
            ('commonName2', 'test common name'),  # invalid subject attribute
            ('organizationName', 'test org'),
            ('organizationalUnitName', 'test ou')
        ),
        'subject_alt_names': ('www.test.org', 'www.test.net'),
        'key_usage': {'digital_signature': True, 'key_encipherment': True},
        'key_size': 2048,
        'hash_algorithm': 'SHA256'
    },
    {
        'subject': (
            ('commonName', 'test common name'),
            ('organizationName', 'test org'),
            ('organizationalUnitName', 'test ou')
        ),
        'subject_alt_names': ('www.test.org', 'www.test.net'),
        'key_usage': {'digital_signature': True, 'key_encipherment': True},
        'key_size': 1024,  # weak key size
        'hash_algorithm': 'SHA256'
    },
    {
        'subject': (  # empty policy
            ('businessCategory', ''),
            ('commonName', ''),
            ('countryName', ''),
            ('dnQualifier', ''),
            ('domainComponent', ''),
            ('emailAddress', ''),
            ('generationQualifier', ''),
            ('givenName', ''),
            ('jurisdictionCountryName', ''),
            ('jurisdictionLocalityName', ''),
            ('jurisdictionStateOrProvinceName', ''),
            ('localityName', ''),
            ('organizationalUnitName', ''),
            ('organizationName', ''),
            ('postalAddress', ''),
            ('postalCode', ''),
            ('pseudonym', ''),
            ('serialNumber', ''),
            ('stateOrProvinceName', ''),
            ('streetAddress', ''),
            ('surname', ''),
            ('title', ''),
            ('userID', ''),
            ('x500UniqueIdentifier', '')
        ),
        'subject_alt_names': ('',),
        'key_usage': {
            'digital_signature': False,
            'content_commitment': False,
            'key_encipherment': False,
            'data_encipherment': False,
            'key_agreement': False,
            'key_cert_sign': False,
            'crl_sign': False,
            'encipher_only': False,
            'decipher_only': False
        },
        'basic_constraints': {
            'ca': False,
            'path_length': None
        },
        'key_size': 2048,
        'hash_algorithm': 'SHA256'
    },
)

sample_shares = (
    ('6046ea4c-32a5-47a1-be00-be74110aa566', 107, 15288, 39035651000266523388257098428752),
    ('6046ea4c-32a5-47a1-be00-be74110aa566', 107, 102107, 85125624943142962423672069361793),
    ('6046ea4c-32a5-47a1-be00-be74110aa566', 107, 277117, 115567609181130133573148417181602),
    ('6046ea4c-32a5-47a1-be00-be74110aa566', 107, 628607, 156452236128381489434170869187611)
)
