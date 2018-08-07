#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Unit tests for exports from cloaked
"""

import unittest
import itertools

from cloaked import *  # ('Share', 'decrypt', 'decrypt_str', 'encrypt', 'encrypt_str', 'merge', 'split')


class UnitTests(unittest.TestCase):
    def test_encrypt_decrypt(self):
        for i in (0, 32, 64, 128, 256):
            rsa_key = RSA.generate(2048)
            pub_key = rsa_key.publickey()
            msg = get_random_str(i)
            enc_msg = encrypt_str(msg, pub_key)
            self.assertNotEqual(msg, enc_msg)
            self.assertEqual(msg, decrypt_str(enc_msg, rsa_key))

    def test_split_merge(self):
        for n, m in ((2, 3), (3, 5)):
            for i in (1, 32, 64, 128, 256):
                secret = get_random_str(i)
                shares = split(secret, n, m)
                self.assertEqual(m, len(shares))
                for n_shares in itertools.permutations(shares, r=n):
                    print(secret)
                    r_secret = merge(n_shares)
                    self.assertEqual(secret, r_secret)
