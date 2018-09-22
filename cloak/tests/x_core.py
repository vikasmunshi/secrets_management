#!/usr/bin/env python3
# -*- coding: utf-8 -*-
""" Unit tests for cloak.core """
import unittest

import cloak
from .test_data import sample_shares


class UnitTestsCore(unittest.TestCase):
    def test_Share(self):
        """check Share has i,p,x,y attributes and encrypt method"""
        self.assertTrue(all(hasattr(cloak.Share, attrib) for attrib in ('i', 'p', 'x', 'y')))
        self.assertTrue(callable(cloak.Share.encrypt))

    def test_Share_EncryptedShare(self):
        """check EncryptedShare is serializable"""
        self.assertTrue(all(hasattr(cloak.EncryptedShare, attrib) for attrib in ('i', 'p', 'x', 'y')))
        for share in (cloak.Share(*s) for s in sample_shares):
            key = cloak.new_rsa_key(2048)
            enc_share = share.encrypt(key.public_key())
            self.assertIsInstance(enc_share.y, str)
            enc_share_str = enc_share.dumps()
            self.assertIsInstance(enc_share_str, str)
            self.assertEqual(enc_share, cloak.EncryptedShare.loads(enc_share_str))
            self.assertEqual(share, cloak.EncryptedShare.loads(enc_share_str).decrypt(key))

    def test_random(self):
        """check StrongRandom"""
        rand = cloak.StrongRandom()
        random_int = rand.randint(0, 100)
        self.assertIsInstance(random_int, int)

    def test_random_bytes(self):
        """check get_random_bytes(x) ∈ bytes and len(get_random_bytes(x)) = x"""
        for i in (8, 32, 64, 128, 256):
            random_bytes = cloak.get_random_bytes(i)
            self.assertIsInstance(random_bytes, bytes)
            self.assertEqual(i, len(random_bytes))

    def test_random_str(self):
        """check random_str(x) ∈ str and len(random_str(x)) = x"""
        for i in (8, 32, 64, 128, 256):
            msg = cloak.get_random_str(i)
            self.assertIsInstance(msg, str)
            self.assertEqual(i, len(msg))
