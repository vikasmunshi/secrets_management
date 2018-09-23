#!/usr/bin/env python3
# -*- coding: utf-8 -*-
""" Unit tests for cloak.secret_sharing """
import unittest
import cloak


class UnitTestsSplit(unittest.TestCase):
    from .test_data import sample_shares, rsa_key, rsa_pub_key
    shares = tuple(cloak.Share(*share) for share in sample_shares)

    def test_Share_ShareEncrypted(self):
        for sample_share, share in zip(self.sample_shares, self.shares):
            self.assertEqual(sample_share[0], share.id)
            self.assertEqual(sample_share[1], share.mersenne)
            self.assertEqual(sample_share[2], share.x)
            self.assertEqual(sample_share[3], share.y)
            self.assertEqual(share.modulus, 2 ** share.mersenne - 1)
            self.assertEqual(len(sample_share), share.count_distinct_shares(self.shares))
            enc_share = share.encrypt(custodian_pub_key=self.rsa_pub_key)
            self.assertIsInstance(enc_share, cloak.ShareEncrypted)
            self.assertEqual(share.id, enc_share.id)
            self.assertEqual(share.mersenne, enc_share.mersenne)
            self.assertEqual(share.x, enc_share.x)
            self.assertIsInstance(enc_share.y, str)
            self.assertEqual(share.y, int(cloak.decrypt(enc_share.y, private_key=self.rsa_key)))
            self.assertEqual(share, enc_share.decrypt(custodian_pvt_key=self.rsa_key))

    def test__find_suitable_mersenne_prime(self):
        from secrets import SystemRandom
        rand = SystemRandom()
        for i in (32, 64, 128, 256):
            x = rand.randint(0, 2 ** i)
            m, p = cloak.secret_sharing._find_suitable_mersenne_prime(x)
            self.assertIsInstance(m, int)
            self.assertIsInstance(p, int)
            self.assertGreater(p, x)
            for m_ in (i for i in cloak.known_mersenne_primes if 100 < i < m):
                self.assertLess(cloak.mersenne_prime(m_), x)
            self.assertIn(m, cloak.known_mersenne_primes)

    def test__modulo_inverse(self):
        from secrets import SystemRandom
        rand = SystemRandom()
        for i in (32, 64, 128, 256):
            x = rand.randint(0, 2 ** i)
            _, p = cloak.secret_sharing._find_suitable_mersenne_prime(x)
            y = cloak.secret_sharing._modulo_inverse(x=x, modulus=p)
            self.assertEqual(1, (x * y) % p)

    def test_split_un_split(self):
        from itertools import permutations
        for n, m in ((2, 3), (3, 5)):
            for i in (1, 32, 64, 128, 256):
                secret = cloak.random_str(i)
                shares = cloak.split(secret=secret, recombination_threshold=n, num_shares=m)
                self.assertEqual(m, len(shares))
                for n_shares in permutations(shares, r=n):
                    for n_shares_less_one in permutations(n_shares, r=n - 1):
                        self.assertIsNone(cloak.un_split(n_shares_less_one))  # one less share returns None
                    self.assertEqual(secret, cloak.un_split(n_shares))

        with self.assertRaises(AssertionError) as context:
            cloak.split(secret, 5, 3)
        self.assertIn('invalid n of m specification', str(context.exception))

        with self.assertRaises(AssertionError) as context:
            cloak.split(secret, 1, 5)
        self.assertIn('invalid n of m specification', str(context.exception))

        secret = cloak.random_str(32)
        shares1 = cloak.split(secret=secret, recombination_threshold=3, num_shares=5)
        shares2 = cloak.split(secret=secret, recombination_threshold=3, num_shares=5)
        for n_shares in permutations(shares1 + shares2, r=3):
            if n_shares[0].count_distinct_shares(n_shares) == len(n_shares):
                self.assertEqual(secret, cloak.un_split(n_shares))
            else:
                with self.assertRaises(AssertionError) as context:
                    cloak.un_split(n_shares)
                self.assertIn('shares mismatch or not unique', str(context.exception))

        with self.assertRaises(AssertionError) as context:
            cloak.split('', 3, 5)
        self.assertIn('need a secret to split', str(context.exception))
