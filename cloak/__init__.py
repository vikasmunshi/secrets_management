#!/usr/bin/env python3
# -*- coding: utf-8 -*-
""" Library of secrets management functions """
from os import path
from .crypt import (
    decrypt,
    encrypt,
    mersenne_prime,
    new_rsa_key,
    random_str,
    rsa_decrypt,
    rsa_encrypt,
    rsa_key_from_file,
    rsa_key_to_file,
    rsa_key_to_str,
    rsa_pub_key_from_file,
    rsa_pub_key_to_file,
    rsa_pub_key_to_str,
)
from .csr import (
    check_csr,
    check_csr_str,
    new_certificate_signing_request,
    str_dump_new_certificate_signing_request_and_key,
)
from .policy import (
    BasicConstraints,
    KeyUsage,
    Policy,
    SubjectAttributeOID,
    subject_attribute_names,
)
from .split import (
    Share,
    ShareEncrypted,
    split,
    un_split,
)

from .tests.__main__ import run_tests

__all__ = (
    'BasicConstraints',
    'KeyUsage',
    'Policy',
    'check_csr',
    'check_csr_str',
    'decrypt',
    'encrypt',
    'mersenne_prime',
    'new_certificate_signing_request',
    'new_rsa_key',
    'random_str',
    'rsa_decrypt',
    'rsa_encrypt',
    'rsa_key_from_file',
    'rsa_key_to_file',
    'rsa_key_to_str',
    'rsa_pub_key_from_file',
    'rsa_pub_key_to_file',
    'rsa_pub_key_to_str',
    'run_tests',
    'Share',
    'ShareEncrypted',
    'split',
    'str_dump_new_certificate_signing_request_and_key',
    'subject_attribute_names',
    'SubjectAttributeOID',
    'un_split',
)
__author__ = 'Vikas Munshi'
__email__ = 'vikas.munshi@gmail.com'
__license__ = 'GNU GPL3'
__package__ = path.basename(path.dirname(path.abspath(__file__)))
__version__ = '0.3.25627585'
