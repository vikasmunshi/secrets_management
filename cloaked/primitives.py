#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Library of functions
"""
from base64 import b64decode, b64encode
from collections import namedtuple
from io import BytesIO
from string import ascii_letters, digits
from uuid import uuid4

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes, random

Share = namedtuple('Share', ('i', 'p', 'x', 'y'))
# Share(i:str, p:int, x:int, y:int) # id, modulus, x, y

__all__ = ('Share', 'decrypt', 'encrypt', 'get_random_str', 'merge', 'split')


def decrypt(encrypted_message: bytes, private_key: RSA.RsaKey) -> bytes:
    """decrypt encrypted message"""
    enc_msg_bytes = BytesIO(b64decode(encrypted_message))
    enc_key, nonce, tag, cipher_text = (enc_msg_bytes.read(size) for size in (private_key.size_in_bytes(), 16, 16, -1))
    key = PKCS1_OAEP.new(private_key).decrypt(enc_key)
    cipher_aes = AES.new(key, AES.MODE_EAX, nonce)
    return cipher_aes.decrypt_and_verify(cipher_text, tag)


def encrypt(message: bytes, public_key: RSA.RsaKey) -> bytes:
    """encrypt plain text message using random AES key and encrypt AES key using public_key"""
    key = get_random_bytes(32)
    cipher_aes = AES.new(key, AES.MODE_EAX)
    cipher_text, tag = cipher_aes.encrypt_and_digest(message)
    enc_key = PKCS1_OAEP.new(public_key).encrypt(key)
    return b64encode(enc_key + cipher_aes.nonce + tag + cipher_text)


def find_suitable_mersenne_prime(x: int) -> (int, int):
    """smallest (mersenne) prime larger than x; raise ValueError ix x is larger than 2^9941 -1"""
    for m, p in ((m, (2 ** m) - 1) for m in (107, 127, 521, 607, 1279, 2203, 2281, 3217, 4253, 4423, 9689, 9941)):
        # https://oeis.org/A000043
        if p > x:
            return m, p
    raise ValueError('too large value {}'.format(x))


def get_random_str(size: int) -> str:
    rand = random.StrongRandom()
    chars = ascii_letters + digits
    return u''.join(rand.choice(chars) for _ in range(size))


def modulo_inverse(x: int, modulus: int) -> int:
    """multiplicative inverse of x modulo n"""
    # https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm
    a, new_a, b, new_b = 0, 1, modulus, x
    while new_b != 0:
        q = b // new_b
        a, new_a = new_a, a - q * new_a
        b, new_b = new_b, b - q * new_b
    if b > 1:
        raise ValueError('{} is not invertible modulo {}'.format(x, modulus))
    return (modulus + a) if a < 0 else a


def merge(shares: (Share, ...)) -> str:
    """reconstruct secret from shares"""
    # https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing
    shares = tuple(Share(*share) for share in shares)  # accept share as tuple instead of namedtuple
    secret_identifier = shares[0].i
    mersenne = shares[0].p
    assert all(s.i == secret_identifier and s.p == mersenne for s in shares), 'shares must be from same batch'
    prime_modulus = (2 ** mersenne) - 1
    num_shares_to_recombine = len(shares)
    # https://en.wikipedia.org/wiki/Polynomial_interpolation
    f_0 = 0
    for i in range(num_shares_to_recombine):
        numerator, denominator = 1, 1
        for j in range(num_shares_to_recombine):
            if i != j:
                numerator = (numerator * (0 - shares[j].x)) % prime_modulus
                denominator = (denominator * (shares[i].x - shares[j].x)) % prime_modulus
        f_0 = (f_0 + (shares[i].y * numerator * modulo_inverse(denominator, prime_modulus))) % prime_modulus
    try:
        return bytes.fromhex(format(f_0, 'x')).decode()
    except (UnicodeDecodeError, ValueError):
        return ''


def split(secret: str, recombination_threshold: int, num_shares: int) -> (Share, ...):
    """split secret into shares using Shamir's Secret Sharing Algorithm"""
    # https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing
    assert num_shares >= recombination_threshold > 1, 'recombination threshold 1 (or less) is insane'
    secret = secret.encode() if secret else get_random_str(32).encode()  # choose a random secret if secret is empty
    secret_identifier = str(uuid4())
    f_0 = int.from_bytes(secret, byteorder='big', signed=False)
    mersenne, modulus = find_suitable_mersenne_prime(f_0)
    rand = random.StrongRandom()
    coefficients = (f_0,) + tuple(rand.randint(1, modulus - 1) for _ in range(recombination_threshold - 1))
    # value of polynomial defined by coefficients at x in modulo modulus
    f_x = lambda x: sum((a * ((x ** i) % modulus) % modulus) for i, a in enumerate(coefficients)) % modulus
    x_values = set()
    while len(x_values) < num_shares:
        x_values.add(rand.randint(1, 10 ** 6))
    return tuple(Share(i=secret_identifier, p=mersenne, x=x, y=f_x(x)) for x in x_values)
