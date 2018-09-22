#!/usr/bin/env python3
# -*- coding: utf-8 -*-
""" cryptography utils """
from base64 import b64decode, b64encode
from io import BytesIO
from secrets import SystemRandom, token_bytes
from string import ascii_letters, digits

from cryptography.hazmat.backends.openssl.backend import backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

__all__ = (
    'decrypt',
    'encrypt',
    'mersenne_prime',
    'new_rsa_key',
    'random_str',
    'rsa_decrypt',
    'rsa_encrypt',
    'rsa_key_from_file',
    'rsa_key_to_file',
    'rsa_key_to_str',
    'rsa_pub_key_from_file',
    'rsa_pub_key_to_file',
    'rsa_pub_key_to_str',
)


def decrypt(encrypted_message: str, private_key: rsa.RSAPrivateKey) -> str:
    """decrypt encrypted message"""
    encrypted_message_bytes = BytesIO(b64decode(encrypted_message.encode()))
    rsa_key_size_in_bytes = private_key.key_size // 8
    enc_hash, enc_key, iv, tag, cipher_text = (encrypted_message_bytes.read(size)
                                               for size in (rsa_key_size_in_bytes, rsa_key_size_in_bytes, 16, 16, -1))
    key = rsa_decrypt(enc_short_message=enc_key, private_key=private_key)
    message_hash = rsa_decrypt(enc_short_message=enc_hash, private_key=private_key)
    decryptor = Cipher(
        algorithm=algorithms.AES(key),
        mode=modes.GCM(initialization_vector=iv, tag=tag),
        backend=backend
    ).decryptor()
    decryptor.authenticate_additional_data(message_hash)
    return (decryptor.update(cipher_text) + decryptor.finalize()).decode()


def encrypt(message: str, public_key: rsa.RSAPublicKey) -> str:
    """encrypt plain text message using random AES key and encrypt AES key using public_key"""
    message_bytes = message.encode()
    hash_func = hashes.Hash(algorithm=hashes.SHA512(), backend=backend)
    hash_func.update(message_bytes)
    message_hash = hash_func.finalize()
    key = token_bytes(32)
    iv = token_bytes(16)
    encryptor = Cipher(
        algorithm=algorithms.AES(key=key),
        mode=modes.GCM(initialization_vector=iv),
        backend=backend
    ).encryptor()
    encryptor.authenticate_additional_data(message_hash)
    cipher_text = encryptor.update(message_bytes) + encryptor.finalize()
    enc_key = rsa_encrypt(short_message=key, public_key=public_key)
    enc_hash = rsa_encrypt(short_message=message_hash, public_key=public_key)
    return b64encode(enc_hash + enc_key + iv + encryptor.tag + cipher_text).decode()


def mersenne_prime(mersenne: int) -> int:
    known_primes = (2, 3, 5, 7, 13, 17, 19, 31, 61, 89, 107, 127, 521, 607, 1279, 2203, 2281, 3217, 4253, 4423,
                    9689, 9941, 11213, 19937, 21701, 23209, 44497, 86243, 110503, 132049, 216091, 756839, 859433,
                    1257787, 1398269, 2976221, 3021377, 6972593, 13466917, 20996011, 24036583, 25964951,
                    30402457, 32582657, 37156667, 42643801, 43112609)  # https://oeis.org/A000043
    assert mersenne in known_primes, 'number {} not in known mersenne primes {}'.format(mersenne, known_primes)
    return (2 ** mersenne) - 1


def new_rsa_key(key_size: int = 2048) -> rsa.RSAPrivateKey:
    if key_size < 2048:
        raise ValueError('Key size less than 2048 is weak')
    return rsa.generate_private_key(public_exponent=65537, key_size=key_size, backend=backend)


def random_str(size: int) -> str:
    """return random str of letters and digits of size length"""
    rand = SystemRandom()
    chars = ascii_letters + digits
    return u''.join(rand.choice(chars) for _ in range(size))


def rsa_decrypt(enc_short_message: bytes, private_key: rsa.RSAPrivateKey) -> bytes:
    hash_algorithm = hashes.SHA512 if private_key.key_size >= 2048 else hashes.SHA256
    return private_key.decrypt(
        ciphertext=enc_short_message,
        padding=padding.OAEP(
            mgf=padding.MGF1(algorithm=hash_algorithm()),
            algorithm=hash_algorithm(),
            label=None
        )
    )


def rsa_encrypt(short_message: bytes, public_key: rsa.RSAPublicKey) -> bytes:
    hash_algorithm = hashes.SHA512 if public_key.key_size >= 2048 else hashes.SHA256
    return public_key.encrypt(
        plaintext=short_message,
        padding=padding.OAEP(
            mgf=padding.MGF1(algorithm=hash_algorithm()),
            algorithm=hash_algorithm(),
            label=None
        )
    )


def rsa_key_from_file(filename: str) -> rsa.RSAPrivateKey:
    with open(filename) as infile:
        return serialization.load_pem_private_key(
            data=infile.read().encode(),
            password=None,
            backend=backend
        )


def rsa_key_to_file(filename: str, private_key: rsa.RSAPrivateKey) -> None:
    with open(filename, 'w') as outfile:
        outfile.write(rsa_key_to_str(private_key=private_key))


def rsa_key_to_str(private_key: rsa.RSAPrivateKey) -> str:
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ).decode()


def rsa_pub_key_from_file(filename: str) -> rsa.RSAPublicKey:
    with open(filename) as infile:
        return serialization.load_ssh_public_key(
            data=infile.read().encode(),
            backend=backend
        )


def rsa_pub_key_to_file(filename: str, public_key: rsa.RSAPublicKey) -> None:
    with open(filename, 'w') as outfile:
        outfile.write(rsa_pub_key_to_str(public_key=public_key))


def rsa_pub_key_to_str(public_key: rsa.RSAPublicKey) -> str:
    return public_key.public_bytes(
        encoding=serialization.Encoding.OpenSSH,
        format=serialization.PublicFormat.OpenSSH
    ).decode()
