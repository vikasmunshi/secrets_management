#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Library of functions
"""
from base64 import b64decode, b64encode
from collections import namedtuple
from dataclasses import dataclass
from hashlib import sha3_256
from io import BytesIO
from string import ascii_letters, digits

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes, random
from OpenSSL import crypto


@dataclass()
class CSRInfo:
    subject: ((str, str), ...)
    extensions: ((str, bool, str), ...)
    subjectAltName: str = ''


Share = namedtuple('Share', ('i', 'p', 'x', 'y'))  # id, modulus, x, y

__all__ = ('CSRInfo', 'Share', 'decrypt', 'encrypt', 'get_random_str', 'new_csr', 'new_rsa_key', 'merge', 'split')


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


def find_suitable_modulus(x: int) -> int:
    """smallest (mersenne) prime larger than x; raise ValueError ix x is larger than 2^9941 -1"""
    for p in ((2 ** m) - 1 for m in (107, 127, 521, 607, 1279, 2203, 2281, 3217, 4253, 4423, 9689, 9941)):
        # https://oeis.org/A000043
        if p > x:
            return p
    raise ValueError('too large value {}'.format(x))


def get_random_str(size: int) -> str:
    rand = random.StrongRandom()
    chars = ascii_letters + digits
    return u''.join(rand.choice(chars) for _ in range(size))


def inverse(x: int, modulus: int) -> int:
    """multiplicative inverse of x modulo n"""
    # https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm
    a, new_a, b, new_b = 0, 1, modulus, x
    while new_b != 0:
        q = b // new_b
        a, new_a = new_a, a - q * new_a
        b, new_b = new_b, b - q * new_b
    if b > 1:
        raise ValueError('{} is not inevitable modulo {}'.format(x, modulus))
    return (modulus + a) if a < 0 else a


def new_csr(csr_info: CSRInfo, size: int = 2048, signature_hash: bytes = 'sha256', version: int = 3) -> (str, str):
    csr = crypto.X509Req()
    csr.set_version(version)
    csr_subject = csr.get_subject()
    for k, v in csr_info.subject:
        if k in ('CN', 'C', 'ST', 'L', 'O', 'OU'):
            setattr(csr_subject, k, v.encode())
    extensions = csr_info.extensions
    if csr_info.subjectAltName:
        extensions += (('subjectAltName', False, ','.join('DNS:' + s.strip()
                                                          for s in csr_info.subjectAltName.split(','))),)
    csr.add_extensions(tuple(crypto.X509Extension(e[0].encode(), e[1], e[2].encode()) for e in extensions))
    key = crypto.load_privatekey(crypto.FILETYPE_PEM, RSA.generate(size).export_key())
    csr.set_pubkey(key)
    csr.sign(key, signature_hash)
    return (
        crypto.dump_privatekey(crypto.FILETYPE_PEM, key).decode(),
        crypto.dump_certificate_request(crypto.FILETYPE_PEM, csr).decode()
    )


def new_rsa_key(size: int = 2048) -> RSA.RsaKey:
    return RSA.generate(size)


def merge(shares: (Share, ...)) -> bytes:
    """reconstruct secret from shares"""
    shares = tuple(Share(*share) for share in shares)  # accept share as tuple instead of namedtuple
    secret_identifier = shares[0].i
    prime_modulus = shares[0].p
    assert all(s.i == secret_identifier and s.p == prime_modulus for s in shares), 'shares must be from same batch'
    num_shares_to_recombine = len(shares)
    # https://en.wikipedia.org/wiki/Polynomial_interpolation
    f_0 = 0
    for i in range(num_shares_to_recombine):
        numerator, denominator = 1, 1
        for j in range(num_shares_to_recombine):
            if i != j:
                numerator = (numerator * (0 - shares[j].x)) % prime_modulus
                denominator = (denominator * (shares[i].x - shares[j].x)) % prime_modulus
        f_0 = (f_0 + (shares[i].y * numerator * inverse(denominator, prime_modulus))) % prime_modulus
    try:
        secret = bytes.fromhex(format(f_0, 'x'))
    except ValueError:
        return b''
    else:
        return secret if secret_identifier == sha3_256(secret).hexdigest() else b''


def split(secret: bytes, recombination_threshold: int, num_shares: int) -> (Share, ...):
    """split secret into shares using Shamir's Secret Sharing Algorithm"""
    # https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm
    assert num_shares >= recombination_threshold > 1, 'recombination threshold 1 (or less) is insane'
    secret = secret or get_random_str(32).encode()  # choose a random secret if secret is empty
    secret_identifier = sha3_256(secret).hexdigest()
    f_0 = int.from_bytes(secret, byteorder='big', signed=False)
    prime_modulus = find_suitable_modulus(f_0)
    rand = random.StrongRandom()
    coefficients = (f_0,) + tuple(rand.randint(1, prime_modulus - 1) for _ in range(recombination_threshold - 1))
    # value of polynomial defined by coefficients at x in modulo modulus
    f_x = lambda x: sum((a * ((x ** i) % prime_modulus) % prime_modulus)
                        for i, a in enumerate(coefficients)) % prime_modulus

    x_values = set()
    while len(x_values) < num_shares:
        x_values.add(rand.randint(1, 10 ** 6))
    return tuple(Share(i=secret_identifier, p=prime_modulus, x=x, y=f_x(x)) for x in x_values)
