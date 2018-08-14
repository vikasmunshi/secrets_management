#!/usr/bin/env python3
# -*- coding: utf-8 -*-
""" Unit tests for cloak """
import itertools
import json
import unittest

import cloak


class UnitTests(unittest.TestCase):
    csr_info_list = (
        cloak.CSRInfo(
            (('CN', 'common name'), ('C', 'xx'), ('ST', 'state'), ('L', 'city'), ('O', 'org'), ('OU', 'org unit')),
            (('keyUsage', False, 'Digital Signature, Key Encipherment'), ('basicConstraints', False, 'CA:FALSE')),
            ''),
        cloak.CSRInfo(
            (('CN', 'xxx'), ('C', 'xx'), ('ST', 'xx'), ('L', 'x'), ('O', 'o'), ('OU', 'ou')),
            (('keyUsage', True, 'Digital Signature, Key Encipherment'), ('basicConstraints', False, 'CA:TRUE')),
            'www.test.org'),
        cloak.CSRInfo(
            (('CN', 'xxx'), ('C', 'xx'), ('ST', 'xx'), ('L', 'x'), ('O', 'o'), ('OU', 'ou')),
            (('keyUsage', True, 'Digital Signature, Key Encipherment'), ('basicConstraints', True, 'CA:TRUE')),
            'www.test, test.org')
    )

    invalid_csr_info_list = (
        cloak.CSRInfo(
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
        cloak.CSRInfo(
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
        cloak.CSRInfo(
            subject=(
                ('CN', 'common name'),
                ('C', 'XXX'),  # invalid country code
                ('ST', 'state'),
                ('L', 'city'),
                ('O', 'org'),
                ('OU', 'org unit'),
                ('OU', 'org unit2')
            ),
            extensions=(
                ('keyUsage', True, 'Digital Signature, Key Encipherment'),
                ('basicConstraints', True, 'CA:TRUE')
            ),
            subjectAltName='www.test, test.org'
        ),
        cloak.CSRInfo(
            subject=(),  # empty subject
            extensions=(
                ('keyUsage', True, 'Digital Signature, Key Encipherment'),
                ('basicConstraints', True, 'CA:TRUE')
            ),
            subjectAltName='www.test, test.org'
        )
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

    sample_shares = (
        cloak.Share(i='6046ea4c-32a5-47a1-be00-be74110aa566', p=107, x=15288, y=39035651000266523388257098428752),
        cloak.Share(i='6046ea4c-32a5-47a1-be00-be74110aa566', p=107, x=102107, y=85125624943142962423672069361793),
        cloak.Share(i='6046ea4c-32a5-47a1-be00-be74110aa566', p=107, x=277117, y=115567609181130133573148417181602),
        cloak.Share(i='6046ea4c-32a5-47a1-be00-be74110aa566', p=107, x=628607, y=156452236128381489434170869187611)
    )

    def test_CSRInfo(self):
        """check CSRInfo is serializable"""
        for csr_info in self.csr_info_list:
            csr_info_str = csr_info.dumps()
            self.assertIsInstance(csr_info_str, str)
            self.assertEqual(csr_info, cloak.CSRInfo.loads(csr_info_str))

    def test_EncryptedShare(self):
        """check EncryptedShare is serializable"""
        for share in self.sample_shares:
            key = cloak.new_rsa_key(2048)
            enc_share = share.encrypt(key.publickey())
            self.assertIsInstance(enc_share.y, str)
            enc_share_str = enc_share.dumps()
            self.assertIsInstance(enc_share_str, str)
            self.assertEqual(share, cloak.EncryptedShare.loads(enc_share_str).decrypt(key))

    def test_RSA(self):
        """check RSA has RsaKey and generate"""
        key = cloak.RSA.generate(2048)
        self.assertIsInstance(key, cloak.RSA.RsaKey)
        pub_key = key.publickey()
        self.assertIsInstance(pub_key, cloak.RSA.RsaKey)
        self.assertEqual(2048, key.size_in_bits())
        self.assertIsInstance(key.export_key(), bytes)

    def test__find_suitable_mersenne_prime(self):
        """check find_suitable_mersenne_prime(x) returns a tuple (m, p = 2**m -1) such that p is just larger than x"""
        mersenne_primes = (2, 3, 5, 7, 13, 17, 19, 31, 61, 89, 107, 127, 521, 607, 1279, 2203, 2281, 3217, 4253, 4423,
                           9689, 9941, 11213, 19937, 21701, 23209, 44497, 86243, 110503, 132049, 216091, 756839, 859433,
                           1257787, 1398269, 2976221, 3021377, 6972593, 13466917, 20996011, 24036583, 25964951,
                           30402457, 32582657, 37156667, 42643801, 43112609)  # https://oeis.org/A000043
        for i in (32, 64, 128, 256):
            x = cloak.random.StrongRandom().randint(0, 2 ** i)
            self.assertIsInstance(x, int)
            m, p = cloak.secret_sharing.find_suitable_mersenne_prime(x)
            self.assertIsInstance(p, int)
            self.assertLess(x, p)
            self.assertIn(m, mersenne_primes)

    def test__modulo_inverse(self):
        """check modulo_inverse(x, p) ∈ int and x * modulo_inverse(x, p) ≡ 1 mod p"""
        for i in (32, 64, 128, 256):
            x = cloak.random.StrongRandom().randint(0, 2 ** i)
            m, p = cloak.secret_sharing.find_suitable_mersenne_prime(x)
            x_inverse = cloak.secret_sharing.modulo_inverse(x, p)
            self.assertIsInstance(x_inverse, int)
            self.assertEqual(1, (x * x_inverse) % p)

    def test__random(self):
        """check random has StrongRandom"""
        rand = cloak.random.StrongRandom()
        random_int = rand.randint(0, 100)
        self.assertIsInstance(random_int, int)

    def test__random_bytes(self):
        """check get_random_bytes(x) ∈ bytes and len(get_random_bytes(x)) = x"""
        for i in (8, 32, 64, 128, 256):
            random_bytes = cloak.get_random_bytes(i)
            self.assertIsInstance(random_bytes, bytes)
            self.assertEqual(i, len(random_bytes))

    def test__random_str(self):
        """check random_str(x) ∈ str and len(random_str(x)) = x"""
        for i in (8, 32, 64, 128, 256):
            msg = cloak.get_random_str(i)
            self.assertIsInstance(msg, str)
            self.assertEqual(i, len(msg))

    def test__split_un_split(self):
        """check that all permutations of exactly n shares out of m reconstruct the secret and other checks"""
        for n, m in ((2, 3), (3, 5)):
            for i in (1, 32, 64, 128, 256):
                secret = cloak.get_random_str(i)
                shares = json.loads(json.dumps(cloak.split(secret, n, m)))
                self.assertEqual(m, len(shares))
                for n_shares in itertools.permutations(shares, r=n):
                    for n_shares_less_one in itertools.permutations(n_shares, r=n - 1):
                        self.assertIsNone(cloak.un_split(n_shares_less_one))  # one less share returns None
                    self.assertEqual(secret, cloak.un_split(n_shares))

        with self.assertRaises(AssertionError) as context:
            cloak.split(secret, 5, 3)
        self.assertIn('invalid n of m specification', str(context.exception))

        with self.assertRaises(AssertionError) as context:
            cloak.split(secret, 1, 5)
        self.assertIn('invalid n of m specification', str(context.exception))

        with self.assertRaises(AssertionError) as context:
            cloak.un_split(tuple(cloak.Share(i=i, p=n[1], x=n[2], y=n[3]) for i, n in enumerate(shares)))
        self.assertIn('shares must be from same batch', str(context.exception))

        with self.assertRaises(AssertionError) as context:
            cloak.split('', 3, 5)
        self.assertIn('need a secret to split', str(context.exception))

    def test_encrypt_decrypt(self):
        """check decrypt(encrypt(msg)) = msg"""
        for i in (0, 8, 32, 64, 128, 256):
            rsa_key = cloak.new_rsa_key()
            pub_key = rsa_key.publickey()
            msg_str = cloak.get_random_str(i)
            enc_msg = cloak.encrypt(msg_str, pub_key)
            self.assertNotEqual(msg_str, enc_msg)
            self.assertEqual(msg_str, cloak.decrypt(enc_msg, rsa_key))

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
        for invalid_csr_info in self.invalid_csr_info_list:
            self.assertFalse(cloak.validate_csr_info(invalid_csr_info))

    def test_validate_new_csr(self):
        """check csr generated is valid and conforms to inputs"""
        for csr_info in self.csr_info_list:
            key = cloak.new_rsa_key(1024)
            csr = cloak.new_csr(csr_info, key)
            self.assertIsInstance(csr, str)
            req = cloak.pki.crypto.load_certificate_request(cloak.pki.crypto.FILETYPE_PEM, csr)
            self.assertIsInstance(req, cloak.pki.crypto.X509Req)
            req_pub_key = req.get_pubkey().to_cryptography_key().public_numbers()
            self.assertEqual(key.n, req_pub_key.n)
            self.assertEqual(key.e, req_pub_key.e)
            self.assertTrue(cloak.validate_csr(csr, csr_info))
