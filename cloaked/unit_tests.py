#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Unit tests for cloaked
"""
import itertools
import json
import unittest

import cloaked


class UnitTests(unittest.TestCase):
    def test__find_suitable_mersenne_prime(self):
        mersenne_primes = (2, 3, 5, 7, 13, 17, 19, 31, 61, 89, 107, 127, 521, 607, 1279, 2203, 2281, 3217, 4253, 4423,
                           9689, 9941, 11213, 19937, 21701, 23209, 44497, 86243, 110503, 132049, 216091, 756839, 859433,
                           1257787, 1398269, 2976221, 3021377, 6972593, 13466917, 20996011, 24036583, 25964951,
                           30402457, 32582657, 37156667, 42643801, 43112609)  # https://oeis.org/A000043
        for i in (32, 64, 128, 256):
            x = cloaked.primitives.random.StrongRandom().randint(0, 2 ** i)
            self.assertIsInstance(x, int)
            m, p = cloaked.primitives.find_suitable_mersenne_prime(x)
            self.assertIsInstance(p, int)
            self.assertLess(x, p)
            self.assertIn(m, mersenne_primes)

    def test__random_str(self):
        for i in (0, 32, 64, 128, 256):
            msg = cloaked.get_random_str(i)
            self.assertIsInstance(msg, str)
            self.assertEqual(i, len(msg))

    def test__modulo_inverse(self):
        for i in (32, 64, 128, 256):
            x = cloaked.primitives.random.StrongRandom().randint(0, 2 ** i)
            m, p = cloaked.primitives.find_suitable_mersenne_prime(x)
            x_inverse = cloaked.primitives.modulo_inverse(x, p)
            self.assertIsInstance(x_inverse, int)
            self.assertEqual(1, (x * x_inverse) % p)

    def test_encrypt_decrypt(self):
        for i in (0, 32, 64, 128, 256):
            rsa_key = cloaked.new_rsa_key()
            pub_key = rsa_key.publickey()
            msg = cloaked.get_random_str(i)
            enc_msg = cloaked.encrypt(msg.encode(), pub_key)
            self.assertNotEqual(msg, enc_msg.decode())
            self.assertEqual(msg, cloaked.decrypt(enc_msg, rsa_key).decode())

    def test_merge_split(self):
        for n, m in ((2, 3), (3, 5)):
            for i in (0, 1, 32, 64, 128, 256):
                secret = cloaked.get_random_str(i)
                shares = json.loads(json.dumps(cloaked.split(secret, n, m)))
                self.assertEqual(m, len(shares))
                for n_shares in itertools.permutations(shares, r=n):
                    self.assertFalse(cloaked.merge(n_shares[1:]))
                    if i > 0:
                        self.assertEqual(secret, cloaked.merge(n_shares))
                    else:
                        self.assertEqual(32, len(cloaked.merge(n_shares)))

    def test_new__rsa_key(self):
        for i in (1024, 2048):
            key = cloaked.new_rsa_key(i)
            self.assertIsInstance(key, cloaked.RSA.RsaKey)
            self.assertEqual(i, key.size_in_bits())

    def test_new_csr(self):
        for csr_info in (
                cloaked.CSRInfo(
                    subject=(
                            ('CN', 'common name'),
                            ('C', 'xx'),
                            ('ST', 'state'),
                            ('L', 'city'),
                            ('O', 'org'),
                            ('OU', 'org unit')
                    ),
                    extensions=(
                            ('keyUsage', False, 'Digital Signature, Key Encipherment'),
                            ('basicConstraints', False, 'CA:FALSE')
                    ),
                    subjectAltName=''
                ),
                cloaked.CSRInfo(
                    subject=(
                            ('CN', 'xxx'),
                            ('C', 'xx'),
                            ('ST', 'xx'),
                            ('L', 'x'),
                            ('O', 'o'),
                            ('OU', 'ou')
                    ),
                    extensions=(
                            ('keyUsage', True, 'Digital Signature, Key Encipherment'),
                            ('basicConstraints', True, 'CA:TRUE')
                    ),
                    subjectAltName='www.test, test.org'
                )
        ):
            for i in (1024, 2048):
                key, csr = cloaked.new_csr(csr_info, i)
                self.assertIsInstance(key, str)
                self.assertIsInstance(csr, str)
                crypto = cloaked.rsa.crypto
                pvt_key = crypto.load_privatekey(crypto.FILETYPE_PEM, key)
                pub_key = pvt_key.to_cryptography_key().public_key()
                self.assertTrue(pvt_key.check())
                self.assertEqual(i, pvt_key.bits())
                req = crypto.load_certificate_request(crypto.FILETYPE_PEM, csr)
                req_pub_key = req.get_pubkey().to_cryptography_key()
                self.assertEqual(pub_key.public_numbers(), req_pub_key.public_numbers())
                req_subject = tuple((k.decode(), v.decode()) for k, v in req.get_subject().get_components())
                self.assertEqual(sorted(csr_info.subject), sorted(req_subject))
                req_extensions = req.get_extensions()
                self.assertEqual(len(csr_info.extensions) + (1 if csr_info.subjectAltName else 0), len(req_extensions))
                for ext in ((x.get_short_name().decode(), bool(x.get_critical()), x.__str__()) for x in req_extensions):
                    if ext[0] != 'subjectAltName':
                        self.assertIn(ext, csr_info.extensions)
                    else:
                        self.assertFalse(ext[1])
                        csr_info_subject_alt_name = (a.strip() for a in csr_info.subjectAltName.split(','))
                        for subject_alt_name in (a.strip()[len('DNS:'):] for a in ext[2].split(',')):
                            self.assertIn(subject_alt_name, csr_info_subject_alt_name)

    def test_validate_csr_info(self):
        for invalid_csr_info in (
                cloaked.CSRInfo(
                    subject=(
                            ('CN', 'common name'),
                            ('C', 'xx'),
                            ('ST', 'state'),
                            ('L', 'city'),
                            ('O', 'org'),
                            ('OU', 'org unit'),
                            ('OU', 'org unit 2')  # subject OID must be unique
                    ),
                    extensions=(
                            ('keyUsage', False, 'Digital Signature, Key Encipherment'),
                            ('basicConstraints', False, 'CA:FALSE')
                    ),
                    subjectAltName=''
                ),
                cloaked.CSRInfo(
                    subject=(
                            ('CN', 'xxx'),
                            ('C', 'xx'),
                            ('ST', 'xx'),
                            ('L', 'x'),
                            ('O', 'o'),
                            ('OU', 'ou')
                    ),
                    extensions=(
                            ('keyusage', True, 'Digital Signature, Key Encipherment'),  # invalid extension
                            ('basicConstraints', True, 'CA:TRUE')
                    ),
                    subjectAltName='www.test, test.org'
                ),
                cloaked.CSRInfo(
                    subject=(
                            ('CN', 'common name'),
                            ('C', 'XXX'),  # invalid country code
                            ('ST', 'state'),
                            ('L', 'city'),
                            ('O', 'org'),
                            ('OU', 'org unit'),
                            ('OU', 'org unit2')
                    ),
                    extensions=(),
                    subjectAltName=''
                ),
                cloaked.CSRInfo(
                    subject=(),
                    extensions=(),
                    subjectAltName=''
                )
        ):
            self.assertFalse(cloaked.validate_csr_info(invalid_csr_info))
