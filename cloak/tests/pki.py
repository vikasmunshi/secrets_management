#!/usr/bin/env python3
# -*- coding: utf-8 -*-
""" Unit tests for cloak """
import json
import unittest

import cloak


class UnitTestsPKI(unittest.TestCase):
    csr_info_list = (
        {
            'subject': (('CN', 'name'), ('C', 'xx'), ('ST', 'state'), ('L', 'city'), ('O', 'org'), ('OU', 'org unit')),
            'extensions': (('keyUsage', False, 'Digital Signature, Key Encipherment'),),
            'subjectAltName': ''},
        {
            'subject': (('CN', 'xxx'), ('C', 'xx'), ('ST', 'xx'), ('L', 'x'), ('O', 'o'), ('OU', 'ou')),
            'extensions': (('keyUsage', True, 'Digital Signature'), ('basicConstraints', False, 'CA:TRUE')),
            'subjectAltName': 'www.test.org'},
        {
            'subject': (('CN', 'xxx'), ('C', 'xx'), ('ST', 'xx'), ('L', 'x'), ('O', 'o'), ('OU', 'ou')),
            'extensions': (('keyUsage', True, 'Key Encipherment'), ('basicConstraints', True, 'CA:TRUE')),
            'subjectAltName': 'www.test, test.org'}
    )

    invalid_csr_info_list = (
        {
            'subject': (
                ('CN', 'common name'), ('C', 'xx'), ('ST', 'state'), ('L', 'city'), ('O', 'org'), ('OU', 'org unit'),
                ('OU', 'org unit 2')),  # subject OID must be unique
            'extensions': (('keyUsage', False, 'Digital Signature, Key Encipherment'),
                           ('basicConstraints', False, 'CA:FALSE')),
            'subjectAltName': ''
        },
        {
            'subject': (('CN', 'xxx'), ('C', 'xx'), ('ST', 'xx'), ('L', 'x'), ('O', 'o'), ('OU', 'ou')),
            'extensions': (('keyusage', True, 'Digital Signature, Key Encipherment'),  # invalid extension
                           ('basicConstraints', True, 'CA:TRUE')),
            'subjectAltName': 'www.test, test.org'
        },
        {
            'subject': (('CN', 'common name'),
                        ('C', 'XXX'),  # invalid country code
                        ('ST', 'state'), ('L', 'city'), ('O', 'org'), ('OU', 'org unit'), ('OU', 'org unit2')),
            'extensions': (('keyUsage', True, 'Digital Signature, Key Encipherment'),
                           ('basicConstraints', True, 'CA:TRUE')),
            'subjectAltName': 'www.test, test.org'
        },
        {
            'subject': (),  # empty subject
            'extensions': (('keyUsage', True, 'Digital Signature, Key Encipherment'),
                           ('basicConstraints', True, 'CA:TRUE')),
            'subjectAltName': 'www.test, test.org'
        }
    )

    sample_csr = (
        '\n'.join(l.strip() for l in """
        -----BEGIN CERTIFICATE REQUEST-----
        MIIC6jCCAdICAQMwYzEUMBIGA1UEAwwLY29tbW9uIG5hbWUxCzAJBgNVBAYTAnh4
        MQ4wDAYDVQQIDAVzdGF0ZTENMAsGA1UEBwwEY2l0eTEMMAoGA1UECgwDb3JnMREw
        DwYDVQQLDAhvcmcgdW5pdDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
        AM86fLi2dz82Ge0ueM19JpybWD4AfwZYtSnQhm+JyOIU6DlqYb2R58oONsBhhiAm
        m2GYONIY0sYa7g9Yz6nXbGdHE0p+CTUZ84fwc2vydxB+wN/fdaD4dIx+pzQWsrLD
        Q/A2KCmBTk4/nSftDGWgWM1f/Q+oJbVcw4kuUyaIsvGB/902tiQQRdbs1mLkiCKp
        kLjR5oDpQciiDSnC52qdSk4w4u9zsSXNtthtVkNrmjbPELjLrr2zLyXHJhkdE9Ig
        x64PdocLjbQyjMXubiR2ZJts6m/ciMXu9NoQoKasyueazbNfLgaJlp56YlCW6Z1k
        9zhLm0UUzzOsrLhKyCH1PgECAwEAAaBCMEAGCSqGSIb3DQEJDjEzMDEwCwYDVR0P
        BAQDAgWgMAkGA1UdEwQCMAAwFwYDVR0RBBAwDoIMd3d3LnRlc3Qub3JnMA0GCSqG
        SIb3DQEBCwUAA4IBAQA/yIYuhAJe46xRL8QEcvQC4Y2KliM1TJPKjoN37Tsc/JUV
        ou3JVsqU2tHZRUY4CWHCB1adBddRgpIoZyOWCknrB8A73cmI3J8AlBEAGVWtBtrF
        YJfv9EKoLuq9Y9Z2RkwH18GsQ/DChJub0kcy3ldV+d9jLF+gijsuO/aYt0Rm5aXr
        5HnQH60S82875O+9cBxeSUK5P5uI8GEaj75i0W9Z1TKvakJXdgVP5vfHq/kw2Mjw
        Sp55ZsvFUNWHSyDc0U0WhVzUVm8BISY/bWIXGPKDmcvRR8rV90yoiAT3oPpuO6Lw
        aV3Datj0i8Z/KeVicmvAoyD1R2W5BcTFbs7u3gf8
        -----END CERTIFICATE REQUEST-----
        """.splitlines()),
        cloak.CSRInfo(
            (('CN', 'common name'), ('C', 'xx'), ('ST', 'state'), ('L', 'city'), ('O', 'org'), ('OU', 'org unit')),
            (('keyUsage', False, 'Digital Signature, Key Encipherment'), ('basicConstraints', False, 'CA:FALSE')),
            'www.test.org')
    )

    def test_CSRInfo(self):
        """check CSRInfo is serializable"""
        for csr_info in tuple(cloak.pki.CSRInfo.loads(json.dumps(c)) for c in self.csr_info_list):
            csr_info_str = csr_info.dumps()
            self.assertIsInstance(csr_info_str, str)
            self.assertEqual(csr_info, cloak.CSRInfo.loads(csr_info_str))

    def test_RSA(self):
        """check RSA has RsaKey and generate"""
        key = cloak.RSA.generate(2048)
        self.assertIsInstance(key, cloak.RSA.RsaKey)
        pub_key = key.publickey()
        self.assertIsInstance(pub_key, cloak.RSA.RsaKey)
        self.assertEqual(2048, key.size_in_bits())
        self.assertIsInstance(key.export_key(), bytes)

    def test_new__rsa_key(self):
        """check RSA key generation for key-size 1024, 2048, 4096 bits"""
        for i in (1024, 2048, 4096):
            key = cloak.new_rsa_key(i)
            self.assertIsInstance(key, cloak.RSA.RsaKey)
            self.assertEqual(i, key.size_in_bits())
            self.assertTrue(key.can_encrypt())
            self.assertTrue(key.can_sign())

    def test_validate_add_subject_alt_name_extension(self):
        """check add subjectAltName to extensions formats properly"""
        for alt_name in ('test', 'www.test', 'some.domain.com'):
            for sub_alt_name in cloak.pki.add_subject_alt_name_extension((), alt_name)[0][2].split(','):
                self.assertEqual('DNS:{}'.format(alt_name), sub_alt_name)

    def test_validate_csr(self):
        """check validate_csr returns True for a valid csr for a given csr_info"""
        self.assertTrue(cloak.validate_csr(*self.sample_csr))

    def test_validate_csr_info(self):
        """check csr validator catches errors in csr_info"""
        for invalid_csr_info in tuple(cloak.CSRInfo.loads(json.dumps(c)) for c in self.invalid_csr_info_list):
            self.assertFalse(cloak.validate_csr_info(invalid_csr_info))

    def test_validate_new_csr(self):
        """check csr generated is valid and conforms to inputs"""
        for csr_info in tuple(cloak.CSRInfo.loads(json.dumps(c)) for c in self.csr_info_list):
            key = cloak.new_rsa_key(1024)
            csr = cloak.new_csr(csr_info, key)
            self.assertIsInstance(csr, str)
            req = cloak.pki.crypto.load_certificate_request(cloak.pki.crypto.FILETYPE_PEM, csr)
            self.assertIsInstance(req, cloak.pki.crypto.X509Req)
            req_pub_key = req.get_pubkey().to_cryptography_key().public_numbers()
            self.assertEqual(key.n, req_pub_key.n)
            self.assertEqual(key.e, req_pub_key.e)
            self.assertTrue(cloak.validate_csr(csr, csr_info))
