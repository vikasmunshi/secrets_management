#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Library of functions
"""
from collections import namedtuple

from OpenSSL import crypto

from .primitives import RSA

CSRInfo = namedtuple('CSRInfo', ('subject', 'extensions', 'subjectAltName'))
# CSRInfo(subject: ((str, str), ...), extensions: ((str, bool, str), ...), subjectAltName: str)


__all__ = ('CSRInfo', 'new_csr', 'new_rsa_key', 'validate_csr', 'validate_csr_info')


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
    for item, val in csr_info.subject:
        setattr(csr_subject, item, val.encode())
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


def validate_csr(csr: str, csr_info: CSRInfo) -> bool:
    req = crypto.load_certificate_request(crypto.FILETYPE_PEM, csr)
    req_subject = tuple((k.decode(), v.decode()) for k, v in req.get_subject().get_components())
    req_extensions = tuple((x.get_short_name().decode(), bool(x.get_critical()), str(x)) for x in req.get_extensions())
    if csr_info.subjectAltName:
        req_alt_name = tuple(ext for ext in req_extensions if ext[0] == 'subjectAltName')[0]
        csr_alt_names = (a.strip() for a in csr_info.subjectAltName.split(','))
    else:
        req_alt_name = csr_alt_names = ()

    try:
        assert sorted(csr_info.subject) == sorted(req_subject), 'subject does not match'
        assert len(csr_info.extensions) + (1 if csr_info.subjectAltName else 0) == len(req_extensions), 'num extensions'
        assert all(ext in csr_info.extensions for ext in req_extensions if ext[0] != 'subjectAltName'), 'extensions'
        if csr_info.subjectAltName:
            assert req_alt_name[1] is False, 'non critical subjectAltName extension'
            req_alt_names = tuple(a.strip()[len('DNS:'):] for a in req_alt_name[2].split(','))
            assert sorted(csr_alt_names) == sorted(req_alt_names), 'alt names'
    except AssertionError:
        return False
    else:
        return True


def validate_csr_info(csr_info: CSRInfo) -> bool:
    try:
        _, csr = new_csr(csr_info, 1024)
        return validate_csr(csr, csr_info)
    except (AssertionError, crypto.Error):
        return False
