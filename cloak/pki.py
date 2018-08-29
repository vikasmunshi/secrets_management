#!/usr/bin/env python3
# -*- coding: utf-8 -*-
""" Library of PKI functions """
from .core import CSRInfo, RSA, crypto

__all__ = ('CSRInfo', 'new_csr', 'new_rsa_key', 'validate_csr', 'validate_csr_info')


def add_subject_alt_name_extension(extensions: ((str, bool, str), ...), alt_names: str) -> ((str, bool, str), ...):
    return extensions + ((('subjectAltName', False, ', '.join('DNS:' + s.strip() for s in alt_names.split(','))),)
                         if alt_names else ())


def new_csr(csr_info: CSRInfo, rsa_key: RSA.RsaKey, signature_hash: str = 'sha256', version: int = 3) -> str:
    """create CSR """
    csr = crypto.X509Req()
    csr.set_version(version)
    csr_subject = csr.get_subject()
    for item, val in csr_info.subject:
        setattr(csr_subject, item, val.encode())
    extensions = add_subject_alt_name_extension(csr_info.extensions, csr_info.subjectAltName)
    csr.add_extensions(tuple(crypto.X509Extension(e[0].encode(), e[1], e[2].encode()) for e in extensions))
    key = crypto.load_privatekey(crypto.FILETYPE_PEM, rsa_key.export_key())
    csr.set_pubkey(key)
    # noinspection PyTypeChecker
    csr.sign(key, signature_hash)
    return crypto.dump_certificate_request(crypto.FILETYPE_PEM, csr).decode()


def new_rsa_key(size: int = 2048) -> RSA.RsaKey:
    """ Generate new RSA key-pair"""
    return RSA.generate(size)


def validate_csr(csr: str, csr_info: CSRInfo) -> bool:
    """ check csr is valid for csr_info"""
    req = crypto.load_certificate_request(crypto.FILETYPE_PEM, csr)
    req_subject = tuple((k.decode(), v.decode()) for k, v in req.get_subject().get_components())
    req_extensions = tuple((x.get_short_name().decode(), bool(x.get_critical()), str(x)) for x in req.get_extensions())
    csr_info_extensions = add_subject_alt_name_extension(csr_info.extensions, csr_info.subjectAltName)

    try:
        assert len(csr_info.subject) == len(req_subject), 'num subject'
        assert sorted(csr_info.subject) == sorted(req_subject), 'subject'
        assert len(csr_info_extensions) == len(req_extensions), 'num extensions'
        assert sorted(csr_info_extensions) == sorted(req_extensions), 'extensions'
    except AssertionError:
        return False
    else:
        return True


def validate_csr_info(csr_info: CSRInfo) -> bool:
    """ check csr_info for errors"""
    try:
        assert 'CN' in tuple(c[0] for c in csr_info.subject), 'subject CN is required'
        csr = new_csr(csr_info, new_rsa_key(1024))
        return validate_csr(csr, csr_info)
    except (AssertionError, crypto.Error):
        return False
