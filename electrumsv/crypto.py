# ElectrumSV - lightweight Bitcoin client
# Copyright (C) 2018 The Electrum developers
# Copyright (C) 2019-2020 The ElectrumSV Developers
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import base64
import os
import hashlib
import hmac
from typing import Optional, Union

from .exceptions import InvalidPassword


from Cryptodome.Cipher import AES


class InvalidPadding(Exception):
    pass


def append_PKCS7_padding(data: bytes) -> bytes:
    padlen = 16 - (len(data) % 16)
    return data + bytes([padlen]) * padlen


def strip_PKCS7_padding(data: bytes) -> bytes:
    if len(data) % 16 != 0 or len(data) == 0:
        raise InvalidPadding("invalid length")
    padlen = data[-1]
    if not 0 < padlen <= 16:
        raise InvalidPadding("invalid padding byte (out of range)")
    for i in data[-padlen:]:
        if i != padlen:
            raise InvalidPadding("invalid padding byte (inconsistent)")
    return data[0:-padlen]


def aes_encrypt_with_iv(key: bytes, iv: bytes, data: bytes) -> bytes:
    data = append_PKCS7_padding(data)
    return AES.new(key, AES.MODE_CBC, iv).encrypt(data)


def aes_decrypt_with_iv(key: bytes, iv: bytes, data: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, iv)
    data = cipher.decrypt(data)
    try:
        return strip_PKCS7_padding(data)
    except InvalidPadding:
        raise InvalidPassword()


def EncodeAES_base64(secret: bytes, msg: bytes) -> bytes:
    """Returns base64 encoded ciphertext."""
    e = EncodeAES_bytes(secret, msg)
    return base64.b64encode(e)

def EncodeAES_bytes(secret: bytes, msg: bytes) -> bytes:
    iv = bytes(os.urandom(16))
    ct = aes_encrypt_with_iv(secret, iv, msg)
    return iv + ct

def DecodeAES_base64(secret: bytes, ciphertext_b64: Union[bytes, str]) -> bytes:
    ciphertext = bytes(base64.b64decode(ciphertext_b64))
    return DecodeAES_bytes(secret, ciphertext)

def DecodeAES_bytes(secret: bytes, ciphertext: bytes) -> bytes:
    iv, e = ciphertext[:16], ciphertext[16:]
    s = aes_decrypt_with_iv(secret, iv, e)
    return s


def pw_encode(data: str, password: Optional[Union[bytes, str]]) -> str:
    if password is None:
        return data
    secret = sha256d(password)
    return EncodeAES_base64(secret, data.encode("utf8")).decode('utf8')


def pw_decode(data: str, password: Optional[Union[bytes, str]]) -> str:
    if password is None:
        return data
    secret = sha256d(password)
    try:
        return DecodeAES_base64(secret, data).decode('utf8')
    except Exception:
        raise InvalidPassword()


def sha256(data: Union[bytes, str]) -> bytes:
    data_bytes = data.encode("utf8") if isinstance(data, str) else data
    return hashlib.sha256(data_bytes).digest()


def sha256d(data: Union[bytes, str]) -> bytes:
    data_bytes = data.encode("utf8") if isinstance(data, str) else data
    return sha256(sha256(data_bytes))


def hash_160(x: bytes) -> bytes:
    md = hashlib.new('ripemd160')
    md.update(sha256(x))
    return md.digest()


def hmac_oneshot(key: bytes, msg: bytes, digest: str) -> bytes:
    return hmac.digest(key, msg, digest)
