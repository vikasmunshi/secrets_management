#!/usr/bin/env python3
# -*- coding: utf-8 -*-
""" Library of secrets management functions """
from os import path

from .crypt import (
    decrypt,
    encrypt,
    known_mersenne_primes,
    mersenne_prime,
    mersenne_primes,
    new_rsa_key,
    random_str,
    rsa_decrypt,
    rsa_encrypt,
    rsa_key_from_file,
    rsa_key_from_str,
    rsa_key_to_file,
    rsa_key_to_str,
    rsa_pub_key_from_file,
    rsa_pub_key_from_str,
    rsa_pub_key_to_file,
    rsa_pub_key_to_str,
)
from .csr import (
    certificate_signing_request_main,
    check_csr,
    check_csr_str,
    new_certificate_signing_request,
    str_dump_new_certificate_signing_request_and_key,
)
from .io import (
    read_file_url,
    write_file_url,
)
from .secret_sharing import (
    Share,
    ShareEncrypted,
    split,
    un_split,
)
from .template import (
    BasicConstraints,
    KeyUsage,
    Template,
    SubjectAttributeOID,
    subject_attribute_names,
)

__all__ = (
    'BasicConstraints',
    'KeyUsage',
    'Template',
    'certificate_signing_request_main',
    'check_csr',
    'check_csr_str',
    'decrypt',
    'encrypt',
    'known_mersenne_primes',
    'mersenne_prime',
    'mersenne_primes',
    'new_certificate_signing_request',
    'new_rsa_key',
    'random_str',
    'read_file_url',
    'rsa_decrypt',
    'rsa_encrypt',
    'rsa_key_from_file',
    'rsa_key_from_str',
    'rsa_key_to_file',
    'rsa_key_to_str',
    'rsa_pub_key_from_file',
    'rsa_pub_key_from_str',
    'rsa_pub_key_to_file',
    'rsa_pub_key_to_str',
    'Share',
    'ShareEncrypted',
    'split',
    'str_dump_new_certificate_signing_request_and_key',
    'subject_attribute_names',
    'SubjectAttributeOID',
    'un_split',
    'write_file_url',
)
__author__ = 'Vikas Munshi'
__email__ = 'vikas.munshi@gmail.com'
__license__ = 'GNU GPL3'
__package__ = path.basename(path.dirname(path.abspath(__file__)))
__version__ = '0.4.427290'
