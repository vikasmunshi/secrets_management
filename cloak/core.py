#!/usr/bin/env python3
# -*- coding: utf-8 -*-
""" Library of common functions """
from base64 import b64decode, b64encode
from collections import namedtuple
from io import BytesIO
from json import dumps, loads
from string import ascii_letters, digits

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes, random
from OpenSSL import crypto

__all__ = ('CSRInfo', 'EncryptedShare', 'RSA', 'Share', 'StrongRandom', 'crypto', 'decrypt', 'encrypt',
           'get_random_bytes', 'get_random_str')

# CSRInfo(subject: ((str, str), ...), extensions: ((str, bool, str), ...), subjectAltName: str)
CSRInfo = namedtuple('CSRInfo', ('subject', 'extensions', 'subjectAltName'))
CSRInfo.dumps = lambda self: dumps(self._asdict())
CSRInfo.loads = staticmethod(lambda json_str: CSRInfo(**{k: v if k == 'subjectAltName' else tuple(tuple(i) for i in v)
                                                         for k, v in loads(json_str).items()}))

# EncShare(i:str, p:int, x:int, y:str) # id, modulus, x, enc(y)
EncryptedShare = namedtuple('EncryptedShare', ('i', 'p', 'x', 'y'))
EncryptedShare.decrypt = lambda self, pvt_key: Share(self.i, self.p, self.x, int(decrypt(self.y, pvt_key)))
EncryptedShare.dumps = lambda self: dumps(self._asdict())
EncryptedShare.loads = staticmethod(lambda json_str: EncryptedShare(**loads(json_str)))

# Share(i:str, p:int, x:int, y:int) # id, modulus, x, y
Share = namedtuple('Share', ('i', 'p', 'x', 'y'))
Share.encrypt = lambda self, pub_key: EncryptedShare(self.i, self.p, self.x, encrypt(str(self.y), pub_key))

StrongRandom = random.StrongRandom


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
