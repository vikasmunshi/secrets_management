#!/usr/bin/env python3
# -*- coding: utf-8 -*-
""" Unit tests for cloak """
import json
import unittest

import cloak
from .test_data import csr_info_list, invalid_csr_info_list, sample_csr


class UnitTestsPKI(unittest.TestCase):
    def test_new_rsa_key(self):
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
        self.assertTrue(cloak.validate_csr(sample_csr[0], cloak.CSRInfo(*sample_csr[1])))

    def test_validate_csr_info(self):
        """check csr validator catches errors in csr_info"""
        for invalid_csr_info in tuple(cloak.CSRInfo.loads(json.dumps(c)) for c in invalid_csr_info_list):
            self.assertFalse(cloak.validate_csr_info(invalid_csr_info))

    def test_validate_new_csr(self):
        """check csr generated is valid and conforms to inputs"""
        for csr_info in tuple(cloak.CSRInfo.loads(json.dumps(c)) for c in csr_info_list):
            key = cloak.new_rsa_key(1024)
            csr = cloak.new_csr(csr_info, key)
            self.assertIsInstance(csr, str)
            req = cloak.pki.crypto.load_certificate_request(cloak.pki.crypto.FILETYPE_PEM, csr)
            self.assertIsInstance(req, cloak.pki.crypto.X509Req)
            req_pub_key = req.get_pubkey().to_cryptography_key().public_numbers()
            self.assertEqual(key.n, req_pub_key.n)
            self.assertEqual(key.e, req_pub_key.e)
            self.assertTrue(cloak.validate_csr(csr, csr_info))
