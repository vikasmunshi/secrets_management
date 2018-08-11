#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Library of functions
"""
from collections import namedtuple

from Crypto.PublicKey import RSA
from OpenSSL import crypto

CSRInfo = namedtuple('CSRInfo', ('subject', 'extensions', 'subjectAltName'))
# CSRInfo(subject: ((str, str), ...), extensions: ((str, bool, str), ...), subjectAltName: str)


__all__ = ('CSRInfo', 'new_csr', 'new_rsa_key', 'validate_csr_info')


def new_csr(csr_info: CSRInfo, key_size: int = 2048, hash_algorithm: str = 'sha256', version: int = 3) -> (str, str):
    """generate new RSA key and create a CSR
    :param csr_info: CSRInfo(subject: ((str, str), ...), extensions: ((str, bool, str), ...), subjectAltName: str)
    :param key_size: RSA key size in bits, default 2048
    :param hash_algorithm: hash algorithm to use for signing, default sha256
    :param version: CSR version, default 3
    :return: PEM encoded RSA key, PEM encoded CSR """
    csr = crypto.X509Req()
    csr.set_version(version)
    csr_subject = csr.get_subject()
    assert 'CN' in tuple(c[0] for c in csr_info.subject), 'subject CN is required'
    for o, v in csr_info.subject:
        setattr(csr_subject, o, v.encode())
    ext = csr_info.extensions
    if csr_info.subjectAltName:
        ext += (('subjectAltName', False, ','.join('DNS:' + s.strip() for s in csr_info.subjectAltName.split(','))),)
    csr.add_extensions(tuple(crypto.X509Extension(e[0].encode(), e[1], e[2].encode()) for e in ext))
    key_str = new_rsa_key(key_size).export_key()
    key = crypto.load_privatekey(crypto.FILETYPE_PEM, key_str)
    csr.set_pubkey(key)
    # noinspection PyTypeChecker
    csr.sign(key, hash_algorithm)
    return key_str.decode(), crypto.dump_certificate_request(crypto.FILETYPE_PEM, csr).decode()


def new_rsa_key(size: int = 2048) -> RSA.RsaKey:
    return RSA.generate(size)


def validate_csr_info(csr_info: CSRInfo) -> bool:
    try:
        _, csr = new_csr(csr_info, 1024)
    except (AssertionError, crypto.Error):
        return False
    else:
        req = crypto.load_certificate_request(crypto.FILETYPE_PEM, csr)
        req_subject = tuple((k.decode(), v.decode()) for k, v in req.get_subject().get_components())
        return sorted(csr_info.subject) == sorted(req_subject)
