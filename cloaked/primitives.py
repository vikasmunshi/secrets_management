#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Library of functions
"""
from base64 import b64decode, b64encode
from io import BytesIO
from string import ascii_letters, digits

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes, random

__all__ = ('RSA', 'decrypt', 'encrypt', 'get_random_bytes', 'get_random_str', 'random')


def decrypt(encrypted_message: str, private_key: RSA.RsaKey) -> str:
    """decrypt encrypted message"""
    enc_msg_bytes = BytesIO(b64decode(encrypted_message.encode()))
    enc_key, nonce, tag, cipher_text = (enc_msg_bytes.read(size) for size in (private_key.size_in_bytes(), 16, 16, -1))
    key = PKCS1_OAEP.new(private_key).decrypt(enc_key)
    cipher_aes = AES.new(key, AES.MODE_EAX, nonce)
    return cipher_aes.decrypt_and_verify(cipher_text, tag).decode()


def encrypt(message: str, public_key: RSA.RsaKey) -> str:
    """encrypt plain text message using random AES key and encrypt AES key using public_key"""
    key = get_random_bytes(32)
    cipher_aes = AES.new(key, AES.MODE_EAX)
    cipher_text, tag = cipher_aes.encrypt_and_digest(message.encode())
    enc_key = PKCS1_OAEP.new(public_key).encrypt(key)
    return b64encode(enc_key + cipher_aes.nonce + tag + cipher_text).decode()


def get_random_str(size: int) -> str:
    """return random str of letters and digits of size length"""
    rand = random.StrongRandom()
    chars = ascii_letters + digits
    return u''.join(rand.choice(chars) for _ in range(size))
