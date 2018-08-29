#!/usr/bin/env python3
# -*- coding: utf-8 -*-
""" Unit tests for cloak.secret_sharing """
import itertools
import json
import unittest

import cloak


class UnitTestsSecretSharing(unittest.TestCase):
    def test_find_suitable_mersenne_prime(self):
        """check find_suitable_mersenne_prime(x) returns a tuple (m, p = 2**m -1) such that p is just larger than x"""
        mersenne_primes = (2, 3, 5, 7, 13, 17, 19, 31, 61, 89, 107, 127, 521, 607, 1279, 2203, 2281, 3217, 4253, 4423,
                           9689, 9941, 11213, 19937, 21701, 23209, 44497, 86243, 110503, 132049, 216091, 756839, 859433,
                           1257787, 1398269, 2976221, 3021377, 6972593, 13466917, 20996011, 24036583, 25964951,
                           30402457, 32582657, 37156667, 42643801, 43112609)  # https://oeis.org/A000043
        for i in (32, 64, 128, 256):
            x = cloak.StrongRandom().randint(0, 2 ** i)
            self.assertIsInstance(x, int)
            m, p = cloak.secret_sharing.find_suitable_mersenne_prime(x)
            self.assertIsInstance(p, int)
            self.assertLess(x, p)
            self.assertIn(m, mersenne_primes)

    def test_modulo_inverse(self):
        """check modulo_inverse(x, p) ∈ int and x * modulo_inverse(x, p) ≡ 1 mod p"""
        for i in (32, 64, 128, 256):
            x = cloak.StrongRandom().randint(0, 2 ** i)
            m, p = cloak.secret_sharing.find_suitable_mersenne_prime(x)
            x_inverse = cloak.secret_sharing.modulo_inverse(x, p)
            self.assertIsInstance(x_inverse, int)
            self.assertEqual(1, (x * x_inverse) % p)

    def test_split_un_split(self):
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
