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
from typing import cast, Optional, Union

from bitcoinx.aes import aes_decrypt_with_iv, aes_encrypt_with_iv
from bitcoinx.errors import DecryptionError

from .exceptions import InvalidPassword


def EncodeAES_base64(secret: bytes, msg: bytes) -> bytes:
    """Returns base64 encoded ciphertext."""
    e = EncodeAES_bytes(secret, msg)
    return base64.b64encode(e)

def EncodeAES_bytes(secret: bytes, msg: bytes) -> bytes:
    iv = bytes(os.urandom(16))
    ct = cast(bytes, aes_encrypt_with_iv(secret, iv, msg))
    return iv + ct

def DecodeAES_base64(secret: bytes, ciphertext_b64: Union[bytes, str]) -> bytes:
    ciphertext = bytes(base64.b64decode(ciphertext_b64))
    return DecodeAES_bytes(secret, ciphertext)

def DecodeAES_bytes(secret: bytes, ciphertext: bytes) -> bytes:
    iv, e = ciphertext[:16], ciphertext[16:]
    try:
        s = cast(bytes, aes_decrypt_with_iv(secret, iv, e))
    except DecryptionError:
        raise InvalidPassword()
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
        # TODO(technical-debt) Use of `Exception` class.
        raise InvalidPassword()


def sha256(data: Union[bytes, str]) -> bytes:
    data_bytes = data.encode("utf8") if isinstance(data, str) else data
    return hashlib.sha256(data_bytes).digest()


def sha256d(data: Union[bytes, str]) -> bytes:
    data_bytes = data.encode("utf8") if isinstance(data, str) else data
    return sha256(sha256(data_bytes))
