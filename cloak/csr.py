#!/usr/bin/env python3
# -*- coding: utf-8 -*-
""" X509 Certificate Signing Request """
from cryptography import x509
from cryptography.hazmat.backends.openssl.backend import backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
# noinspection PyProtectedMember
from cryptography.x509.oid import _OID_NAMES as OID_NAMES

from .crypt import new_rsa_key, rsa_key_to_str
from .io import read_file_or_url, write_file_or_url
from .template import Template, SubjectAttributeOID

__all__ = (
    'certificate_signing_request_main',
    'check_csr',
    'check_csr_str',
    'new_certificate_signing_request',
    'str_dump_new_certificate_signing_request_and_key',
)


def certificate_signing_request_main(template_filename: str) -> None:
    template = Template.from_file(template_filename)
    policy = read_file_or_url(template.policy)
    key_str, csr_str = str_dump_new_certificate_signing_request_and_key(template)
    write_file_or_url(dict_obj={'key': key_str}, file_url=template.key_store)
    write_file_or_url(dict_obj={'csr': csr_str}, file_url=policy['ra'])


def check_csr(csr: x509.CertificateSigningRequest, template: Template) -> str:
    """ find all differences (errors) between info in csr and template, return empty string if no errors"""
    extensions = {OID_NAMES.get(extension.oid, extension.oid): extension.value for extension in csr.extensions}
    # noinspection PyProtectedMember
    return '\n'.join(error for error in (
        # verify csr signature
        '' if csr.is_signature_valid else 'hmmm... csr signature is not valid!!!',
        # verify signature hash algorithm
        '' if csr.signature_hash_algorithm.name == template.hash_algorithm.lower() else 'hmmm wrong hash algorithm!!!',
        # verify subject matches
        '' if template.subject == tuple((OID_NAMES.get(attrib.oid), attrib.value) for attrib in csr.subject)
        else 'subject mismatch:\n{}\n{}\n'.format(csr.subject, template.subject),
        # verify subjectAltName
        '' if template.subject_alt_names is None and 'subject_alt_names' not in extensions
        else '' if tuple(x.value for x in extensions['subjectAltName']) == template.subject_alt_names
        else 'subject_alt_names mismatch:\n{}\n{}\n'.format(extensions['subjectAltName'], template.subject_alt_names),
        # verify basicConstraints ca
        '' if extensions['basicConstraints'].ca == template.basic_constraints.ca
        else 'basicConstraints ca mismatch:\n{}\n{}\n'.format(extensions['basicConstraints'].ca,
                                                              template.basic_constraints.ca),
        # verify basicConstraints path_length
        '' if extensions['basicConstraints'].path_length == template.basic_constraints.path_length
        else 'basicConstraints path_length mismatch:\n{}\n{}\n'.format(extensions['basicConstraints'].path_length,
                                                                       template.basic_constraints.path_length),
        # verify keyUsage
        '' if template.key_usage is None and 'keyUsage' not in extensions
        else '' if all((
            extensions['keyUsage'].digital_signature == template.key_usage.digital_signature,
            extensions['keyUsage'].content_commitment == template.key_usage.content_commitment,
            extensions['keyUsage'].key_encipherment == template.key_usage.key_encipherment,
            extensions['keyUsage'].data_encipherment == template.key_usage.data_encipherment,
            extensions['keyUsage'].key_agreement == template.key_usage.key_agreement,
            extensions['keyUsage'].key_cert_sign == template.key_usage.key_cert_sign,
            extensions['keyUsage'].crl_sign == template.key_usage.crl_sign,
            extensions['keyUsage']._encipher_only == template.key_usage.encipher_only,
            extensions['keyUsage']._decipher_only == template.key_usage.decipher_only,
        ))
        else 'keyUsage mismatch:\n{}\n{}\n'.format(extensions['keyUsage'], template.key_usage),
        # verify KeySize
        '' if template.key_size == csr.public_key().key_size
        else 'KeySize mismatch:\n{}\n{}\n'.format(csr.public_key().key_size, template.key_size),
        # verify KeySize >= 2048
        '' if csr.public_key().key_size >= 2048 else 'weak key size {}'.format(csr.public_key().key_size)

    ) if error != '')


def check_csr_str(csr: str, template: Template) -> str:
    return check_csr(csr=x509.load_pem_x509_csr(data=csr.encode(), backend=backend), template=template)


def new_certificate_signing_request(template: Template, rsa_key: rsa.RSAPrivateKey) -> x509.CertificateSigningRequest:
    csr = x509.CertificateSigningRequestBuilder(
        subject_name=x509.Name(
            tuple(x509.NameAttribute(SubjectAttributeOID[k].value, v) for k, v in template.subject))
    ).add_extension(
        x509.BasicConstraints(
            ca=template.basic_constraints.ca,
            path_length=template.basic_constraints.path_length
        ),
        critical=True
    )
    if template.subject_alt_names:
        csr = csr.add_extension(
            x509.SubjectAlternativeName(tuple(x509.DNSName(s) for s in template.subject_alt_names)),
            critical=False
        )
    if template.key_usage:
        csr = csr.add_extension(
            x509.KeyUsage(
                digital_signature=template.key_usage.digital_signature,
                content_commitment=template.key_usage.content_commitment,
                key_encipherment=template.key_usage.key_encipherment,
                data_encipherment=template.key_usage.data_encipherment,
                key_agreement=template.key_usage.key_agreement,
                key_cert_sign=template.key_usage.key_cert_sign,
                crl_sign=template.key_usage.crl_sign,
                encipher_only=template.key_usage.encipher_only,
                decipher_only=template.key_usage.decipher_only
            ),
            critical=True
        )
    csr = csr.sign(rsa_key, getattr(hashes, template.hash_algorithm)(), backend)
    csr_errors = check_csr(csr=csr, template=template)
    assert csr_errors == '', csr_errors
    return csr


def str_dump_new_certificate_signing_request_and_key(template: Template) -> (str, str):
    rsa_key = new_rsa_key(key_size=template.key_size)
    return (
        rsa_key_to_str(private_key=rsa_key),
        new_certificate_signing_request(template, rsa_key).public_bytes(encoding=serialization.Encoding.PEM).decode()
    )
