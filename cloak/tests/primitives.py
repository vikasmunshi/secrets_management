#!/usr/bin/env python3
# -*- coding: utf-8 -*-
""" Unit tests for cloak """
import unittest

import cloak


class UnitTestsPrimitives(unittest.TestCase):
    def test_encrypt_decrypt(self):
        """check decrypt(encrypt(msg)) = msg"""
        for i in (0, 8, 32, 64, 128, 256):
            rsa_key = cloak.new_rsa_key()
            pub_key = rsa_key.publickey()
            msg_str = cloak.get_random_str(i)
            enc_msg = cloak.encrypt(msg_str, pub_key)
            self.assertNotEqual(msg_str, enc_msg)
            self.assertEqual(msg_str, cloak.decrypt(enc_msg, rsa_key))

    def test_random(self):
        """check random has StrongRandom"""
        rand = cloak.random.StrongRandom()
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
