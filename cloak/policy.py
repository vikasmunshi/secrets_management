#!/usr/bin/env python3
# -*- coding: utf-8 -*-
""" X509 CSR Policy """
from __future__ import annotations

from dataclasses import asdict, dataclass
from difflib import get_close_matches
from enum import Enum
from json import dump, load

from cryptography import x509

__all__ = (
    'BasicConstraints',
    'KeyUsage',
    'Policy',
    'SubjectAttributeOID',
    'subject_attribute_names',
)


@dataclass(frozen=True)
class BasicConstraints:
    ca: bool = False
    path_length: int = None


@dataclass(frozen=True)
class KeyUsage:
    digital_signature: bool = False
    content_commitment: bool = False
    key_encipherment: bool = False
    data_encipherment: bool = False
    key_agreement: bool = False
    key_cert_sign: bool = False
    crl_sign: bool = False
    encipher_only: bool = False
    decipher_only: bool = False


@dataclass(frozen=True)
class Policy:
    subject: ((str, str), ...)
    subject_alt_names: tuple = None
    key_usage: KeyUsage = None
    basic_constraints: BasicConstraints = BasicConstraints()
    key_size: int = 2048
    hash_algorithm: str = 'SHA256'

    def __post_init__(self):
        policy_errors = self.policy_errors
        assert policy_errors == '', policy_errors

    def to_dict(self) -> to_dict:
        return asdict(self, dict_factory=lambda t: {x[0]: x[1] for x in t if x[1]})

    @staticmethod
    def from_dict(dict_obj: to_dict) -> Policy:
        return Policy(
            subject=tuple(tuple(x) for x in dict_obj['subject'] if x[1]),
            subject_alt_names=tuple(x for x in dict_obj.get('subject_alt_names', ()) if x) or None,
            key_usage=KeyUsage(**dict_obj['key_usage']) if dict_obj.get('key_usage') else None,
            basic_constraints=BasicConstraints(**dict_obj.get('basic_constraints', {})),
            key_size=dict_obj.get('key_size', 2048),
            hash_algorithm=dict_obj.get('hash_algorithm', 'SHA256')
        )

    @staticmethod
    def from_file(filename: str) -> Policy:
        with open(filename) as infile:
            return Policy.from_dict(load(infile))

    def to_file(self, filename: str) -> None:
        with open(filename, 'w') as outfile:
            dump(self.to_dict(), outfile, indent=2)

    @property
    def policy_errors(self) -> str:
        return '\n'.join(error for error in (
            '' if isinstance(self.subject, tuple) else 'subject error {}'.format(self.subject),
            *tuple(
                '' if isinstance(sub_attrib, tuple) and len(sub_attrib) == 2
                else 'subject error {}'.format(sub_attrib)
                for sub_attrib in self.subject
            ),
            *tuple(
                '' if attrib[0] in subject_attribute_names
                else 'attribute error {}\nperhaps you meant one of: {}\nall possible values are: {}'.format(
                    attrib[0],
                    ' OR '.join(get_close_matches(attrib[0], subject_attribute_names) or subject_attribute_names),
                    ' '.join(subject_attribute_names)
                )
                for attrib in self.subject
            ),
            '' if all(s[1] != '' for s in self.subject)
            else 'subject error {}'.format(self.subject),
            '' if len(self.subject) > 0
            else 'subject empty error {}'.format(self.subject),
            '' if self.subject_alt_names is None or all(x != '' for x in self.subject_alt_names)
            else 'subject alt name error {}'.format(self.subject_alt_names),
            '' if self.key_usage is None or isinstance(self.key_usage, KeyUsage)
            else 'key_usage error {}'.format(self.key_usage),
            '' if isinstance(self.basic_constraints, BasicConstraints)
            else 'basic_constraints error {}'.format(self.basic_constraints),
            '' if isinstance(self.key_size, int) and self.key_size in (2048, 4096, 8192)
            else 'key_size error {}; should be 2048 or 4096 or 8192'.format(self.key_size),
            '' if isinstance(self.hash_algorithm, str) and self.hash_algorithm in ('SHA256', 'SHA384', 'SHA512')
            else 'hash_algorithm error {}, allowed values SHA256 SHA384 SHA512'.format(self.hash_algorithm),
        ) if error != '')


class SubjectAttributeOID(Enum):
    businessCategory = x509.oid.ObjectIdentifier('2.5.4.15')
    commonName = x509.oid.ObjectIdentifier('2.5.4.3')
    countryName = x509.oid.ObjectIdentifier('2.5.4.6')
    dnQualifier = x509.oid.ObjectIdentifier('2.5.4.46')
    domainComponent = x509.oid.ObjectIdentifier('0.9.2342.19200300.100.1.25')
    emailAddress = x509.oid.ObjectIdentifier('1.2.840.113549.1.9.1')
    generationQualifier = x509.oid.ObjectIdentifier('2.5.4.44')
    givenName = x509.oid.ObjectIdentifier('2.5.4.42')
    jurisdictionCountryName = x509.oid.ObjectIdentifier('1.3.6.1.4.1.311.60.2.1.3')
    jurisdictionLocalityName = x509.oid.ObjectIdentifier('1.3.6.1.4.1.311.60.2.1.1')
    jurisdictionStateOrProvinceName = x509.oid.ObjectIdentifier('1.3.6.1.4.1.311.60.2.1.2')
    localityName = x509.oid.ObjectIdentifier('2.5.4.7')
    organizationalUnitName = x509.oid.ObjectIdentifier('2.5.4.11')
    organizationName = x509.oid.ObjectIdentifier('2.5.4.10')
    postalAddress = x509.oid.ObjectIdentifier('2.5.4.16')
    postalCode = x509.oid.ObjectIdentifier('2.5.4.17')
    pseudonym = x509.oid.ObjectIdentifier('2.5.4.65')
    serialNumber = x509.oid.ObjectIdentifier('2.5.4.5')
    stateOrProvinceName = x509.oid.ObjectIdentifier('2.5.4.8')
    streetAddress = x509.oid.ObjectIdentifier('2.5.4.9')
    surname = x509.oid.ObjectIdentifier('2.5.4.4')
    title = x509.oid.ObjectIdentifier('2.5.4.12')
    userID = x509.oid.ObjectIdentifier('0.9.2342.19200300.100.1.1')
    x500UniqueIdentifier = x509.oid.ObjectIdentifier('2.5.4.45')


subject_attribute_names = tuple(a.name for a in SubjectAttributeOID)
