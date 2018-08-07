#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Library of functions
"""

import base64
import binascii
import collections
import hashlib
import io
import string

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes, random

__all__ = ('Share', 'RSA', 'decrypt', 'decrypt_str', 'encrypt', 'encrypt_str', 'get_random_str', 'merge', 'split')
__author__ = 'Vikas Munshi'
__email__ = 'vikas.munshi@gmail.com'
__license__ = 'GNU GPL3'
__package__ = 'cloaked'
__version__ = '0.0.1'

Share = collections.namedtuple('Share', ('i', 'p', 'x', 'y'))  # id, modulus, x, y


def decrypt(encrypted_message: bytes, private_key: RSA.RsaKey) -> bytes:
    """decrypt encrypted message"""
    enc_msg_bytes = io.BytesIO(base64.b64decode(encrypted_message))
    enc_key, nonce, tag, cipher_text = (enc_msg_bytes.read(size) for size in (private_key.size_in_bytes(), 16, 16, -1))
    key = PKCS1_OAEP.new(private_key).decrypt(enc_key)
    cipher_aes = AES.new(key, AES.MODE_EAX, nonce)
    return cipher_aes.decrypt_and_verify(cipher_text, tag)


def decrypt_str(encrypted_message: str, private_key: RSA.RsaKey) -> str:
    return decrypt(encrypted_message.encode(), private_key).decode()


def encrypt(message: bytes, public_key: RSA.RsaKey) -> bytes:
    """encrypt plain text message using random AES key and encrypt AES key using public_key"""
    key = get_random_bytes(32)
    cipher_aes = AES.new(key, AES.MODE_EAX)
    cipher_text, tag = cipher_aes.encrypt_and_digest(message)
    enc_key = PKCS1_OAEP.new(public_key).encrypt(key)
    return base64.b64encode(enc_key + cipher_aes.nonce + tag + cipher_text)


def encrypt_str(message: str, public_key: RSA.RsaKey) -> str:
    return encrypt(message.encode(), public_key).decode()


def f(x: int, coefficients: (int, ...), modulus: int) -> int:
    """value of polynomial defined by coefficients at x in modulo modulus"""
    return sum((a * ((x ** i) % modulus) % modulus) for i, a in enumerate(coefficients)) % modulus


def find_suitable_modulus(x: int) -> int:
    """smallest (mersenne) prime larger than x; raise ValueError ix x is larger than 2^9941 -1"""
    for p in ((2 ** m) - 1 for m in (127, 521, 607, 1279, 2281, 3217, 4253, 9689, 9941)):
        if p > x:
            return p
    raise ValueError('too large value {}'.format(x))


def gcd_extended(a: int, b: int) -> (int, int, int):
    """Euler's algorithm for GCD extended for calculating modulo inverse"""
    if a == 0:
        return b, 0, 1
    else:
        r, c, d = gcd_extended(b % a, a)
        return r, d - (b // a) * c, c


def get_random_str(size: int) -> str:
    rand = random.StrongRandom()
    chars = string.ascii_letters + string.digits
    return u''.join(rand.choice(chars) for _ in range(size))


def invert(x: int, modulus: int) -> int:
    """multiplicative inverse of x modulo modulus"""
    return gcd_extended(modulus, abs(x % modulus))[2]


def merge(shares: (Share, ...)) -> str:
    """reconstruct secret from shares"""
    shares = tuple(Share(*s) for s in shares)  # accept share tuple instead of namedtuple
    secret_identifier = shares[0].i
    prime_modulus = shares[0].p
    assert all(s.i == secret_identifier and s.p == prime_modulus for s in shares), 'shares must be from same batch'
    num_shares_to_recombine = len(shares)
    f_0 = 0
    for i in range(num_shares_to_recombine):
        numerator, denominator = 1, 1
        for j in range(num_shares_to_recombine):
            if i != j:
                numerator = (numerator * (0 - shares[j].x)) % prime_modulus
                denominator = (denominator * (shares[i].x - shares[j].x)) % prime_modulus
            lagrange = numerator * invert(denominator, prime_modulus)
            f_0 = (f_0 + (shares[i].y * lagrange)) % prime_modulus
    try:
        secret_bytes = binascii.unhexlify(format(f_0, 'x'))
        assert secret_identifier == hashlib.sha3_256(secret_bytes).hexdigest(), 'hash did not match'
        secret = secret_bytes.decode('utf-8')
    except (AssertionError, binascii.Error, UnicodeDecodeError):
        raise
    else:
        return secret


def split(secret: str, recombination_threshold: int, num_shares: int) -> (Share, ...):
    """split secret into shares using Shamir's Secret Sharing https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing"""
    assert num_shares >= recombination_threshold > 1, 'recombination threshold 1 (or less) is insane'
    secret = secret or get_random_str(32)  # choose a random secret if secret is empty
    secret_bytes = secret.encode('utf-8')
    secret_identifier = hashlib.sha3_256(secret_bytes).hexdigest()
    f_0 = int(binascii.hexlify(secret_bytes), 16)
    prime_modulus = find_suitable_modulus(f_0)
    rand = random.StrongRandom()
    polynomial = (f_0,) + tuple(rand.randint(1, prime_modulus - 1) for _ in range(recombination_threshold - 1))
    x_values = set()
    while len(x_values) < num_shares: x_values.add(rand.randint(1, 10 ** 6))
    return tuple(Share(i=secret_identifier, p=prime_modulus, x=x, y=f(x, polynomial, prime_modulus)) for x in x_values)
