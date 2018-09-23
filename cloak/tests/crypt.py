#!/usr/bin/env python3
# -*- coding: utf-8 -*-
""" Unit tests for cloak.crypt """
import unittest

import cloak


class UnitTestsCrypt(unittest.TestCase):
    from .test_data import rsa_key, rsa_key_pairs, random_strings

    def test_decrypt_encrypt(self):
        for rsa_key, rsa_pub_key in self.rsa_key_pairs:
            for message in self.random_strings:
                enc_message = cloak.encrypt(message=message, public_key=rsa_pub_key)
                self.assertIsInstance(enc_message, str)
                self.assertNotEqual(message, enc_message)
                dec_message = cloak.decrypt(encrypted_message=enc_message, private_key=rsa_key)
                self.assertIsInstance(dec_message, str)
                self.assertEqual(message, dec_message)
                with self.assertRaises(ValueError):
                    cloak.decrypt(encrypted_message=enc_message, private_key=self.rsa_key)
                with self.assertRaises(AttributeError):
                    cloak.encrypt(message=b'', public_key=rsa_pub_key)
                    cloak.decrypt(encrypted_message=enc_message, private_key=rsa_pub_key)
                    cloak.encrypt(message=message, public_key=rsa_key)

    def test_known_mersenne_primes(self):
        self.assertEqual(
            cloak.known_mersenne_primes,
            (2, 3, 5, 7, 13, 17, 19, 31, 61, 89, 107, 127, 521, 607, 1279, 2203, 2281, 3217, 4253, 4423, 9689, 9941,
             11213, 19937, 21701, 23209, 44497, 86243, 110503, 132049, 216091, 756839, 859433, 1257787, 1398269,
             2976221, 3021377, 6972593, 13466917, 20996011, 24036583, 25964951, 30402457, 32582657, 37156667,
             42643801, 43112609)
        )

    def test_mersenne_prime(self):
        from math import log2
        from secrets import SystemRandom
        rand = SystemRandom()
        for x in tuple(rand.randint(1, 10 ^ 9) for _ in range(100)) + cloak.known_mersenne_primes[0:10]:
            if x in cloak.known_mersenne_primes:
                m = cloak.mersenne_prime(x)
                self.assertIsInstance(m, int)
                self.assertEqual(x, int(log2(m + 1)))
            else:
                with self.assertRaises(AssertionError):
                    cloak.mersenne_prime(x)

    def test_mersenne_primes(self):
        from math import log2
        from types import GeneratorType
        mp = cloak.mersenne_primes()
        self.assertIsInstance(mp, GeneratorType)
        for m, p in mp:
            self.assertEqual(m, int(log2(p + 1)))

    def test_new_rsa_key(self):
        for size in (2048, 4096):
            rsa_key = cloak.new_rsa_key(size)
            self.assertIsInstance(rsa_key, cloak.crypt.rsa.RSAPrivateKey)
            self.assertEqual(size, rsa_key.key_size)
            self.assertEqual(65537, rsa_key.public_key().public_numbers().e)
        with self.assertRaises(ValueError):
            for size in (512, 4000):
                cloak.new_rsa_key(size)

    def test_random_str(self):
        for size in range(10, 100):
            random_str = cloak.random_str(size)
            self.assertIsInstance(random_str, str)
            self.assertEqual(size, len(random_str))
        with self.assertRaises(TypeError):
            cloak.random_str(10.0)
            cloak.random_str('abc')

    def test_rsa_encrypt_decrypt(self):
        for rsa_key, rsa_pub_key in self.rsa_key_pairs:
            max_len = rsa_key.key_size // 16
            for message in self.random_strings:
                message_bytes = message.encode()
                if len(message_bytes) < max_len:
                    enc_msg = cloak.rsa_encrypt(short_message=message_bytes, public_key=rsa_pub_key)
                    self.assertIsInstance(enc_msg, bytes)
                    self.assertNotEqual(message_bytes, enc_msg)
                    dec_msg = cloak.rsa_decrypt(enc_short_message=enc_msg, private_key=rsa_key)
                    self.assertIsInstance(dec_msg, bytes)
                    self.assertEqual(message_bytes, dec_msg)
                else:
                    with self.assertRaises(ValueError):
                        cloak.rsa_encrypt(short_message=message_bytes, public_key=rsa_pub_key)

    def test_rsa_key_to_from_file(self):
        from tempfile import NamedTemporaryFile
        with NamedTemporaryFile() as temp_file:
            filename = temp_file.name
            for rsa_key, rsa_pub_key in self.rsa_key_pairs:
                cloak.rsa_key_to_file(filename=filename, private_key=rsa_key)
                self.assertEqual(
                    rsa_key.private_numbers(),
                    cloak.rsa_key_from_file(filename=filename).private_numbers()
                )
                cloak.rsa_pub_key_to_file(filename=filename, public_key=rsa_pub_key)
                self.assertEqual(
                    rsa_pub_key.public_numbers(),
                    cloak.rsa_pub_key_from_file(filename=filename).public_numbers()
                )

    def test_rsa_key_to_from_str(self):
        for rsa_key, rsa_pub_key in self.rsa_key_pairs:
            rsa_key_str = cloak.rsa_key_to_str(private_key=rsa_key)
            self.assertIsInstance(rsa_key_str, str)
            self.assertEqual(
                rsa_key.private_numbers(),
                cloak.rsa_key_from_str(key_str=rsa_key_str).private_numbers()
            )
            rsa_pub_key_str = cloak.rsa_pub_key_to_str(public_key=rsa_pub_key)
            self.assertIsInstance(rsa_pub_key_str, str)
            self.assertEqual(
                rsa_pub_key.public_numbers(),
                cloak.rsa_pub_key_from_str(pub_key_str=rsa_pub_key_str).public_numbers()
            )
