"""
Functions to aid in informal debug dumping of wallet contents.
"""

# MIT License
#
# Copyright © 2023 Roger Taylor
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the
# rights to use, copy, modify, merge, publish, distribute, sublicense,
# and/or sell copies of the Software, and to permit persons to whom the
# Software is furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
# LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
# WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.


from __future__ import annotations
from typing import cast, TypedDict

from bitcoinx import bip32_build_chain_string, bip32_decompose_chain_string

from ..constants import DerivationPath, DerivationType, pack_derivation_path, ScriptType, \
    unpack_derivation_path
from ..wallet_database.types import TransactionOutputKeyDataRow


class JSONTxoKeyUsage(TypedDict):
    vout: int
    script_type: str
    key_fingerprint: str
    key_derivation: str

class ScriptTypeNames:
    P2PKH           = "p2pkh"

class DerivationTypeNames:
    BIP32           = "bip32:"


def encode_derivation_data(derivation_type: DerivationType, derivation_data2: bytes) -> str:
    """Raises `ValueError` if the script type is unknown."""
    if derivation_type != DerivationType.BIP32_SUBPATH:
        raise ValueError(f"Bad derivation type {derivation_type}")
    # Only corrupt database entries should cause errors from here on. These should not be caught.
    derivation_path = unpack_derivation_path(derivation_data2)
    return DerivationTypeNames.BIP32 + cast(str, bip32_build_chain_string(derivation_path))

def decode_derivation_data(text: str) -> tuple[DerivationType, bytes]:
    """
    Raises `UnicodeDecodeError` if the derivation path is not valid ASCII.
    Raises `ValueError` if the derivation type is unrecognised.
    """
    if text[:6] == DerivationTypeNames.BIP32:
        derivation_path = cast(DerivationPath, bip32_decompose_chain_string(text[6:]))
        return DerivationType.BIP32_SUBPATH, pack_derivation_path(derivation_path)
    raise ValueError(f"Bad derivation type {text[:6]!r}")

def encode_script_type(script_type: ScriptType) -> str:
    if script_type == ScriptType.P2PKH:
        return ScriptTypeNames.P2PKH
    raise ValueError(f"Bad script type {script_type}")

def decode_script_type(text: str) -> ScriptType:
    """
    Raises `UnicodeDecodeError` if the script type name is not valid ASCII.
    Raises `ValueError` if the script type is unrecognised.
    """
    if text == ScriptTypeNames.P2PKH:
        return ScriptType.P2PKH
    raise ValueError(f"Bad script type {text!r}")


def convert_txokeydata_to_jsondata(key_fingerprint: bytes,
        rows: list[TransactionOutputKeyDataRow]) -> list[JSONTxoKeyUsage]:
    return [
        {
            "vout": row.txo_index,
            "script_type": encode_script_type(row.script_type),
            "key_fingerprint": key_fingerprint.hex(),
            "key_derivation": encode_derivation_data(row.derivation_type,
                cast(bytes, row.derivation_data2)),
        } for row in rows
    ]
