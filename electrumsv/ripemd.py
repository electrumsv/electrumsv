import hashlib
from typing import Any

from Cryptodome.Hash import RIPEMD160

_hashlib_new_original: Any = None

def _hashlib_new_replacement(hasher_name: str, *args, **kwargs) -> Any:
    if hasher_name == "ripemd160":
        return RIPEMD160.new(*args, **kwargs)
    return _hashlib_new_original(hasher_name, *args, **kwargs)

assert _hashlib_new_original is None
_hashlib_new_original = hashlib.new
# NOTE(typing) The `hashlib.new` typing is too complicated to bother replicating.
hashlib.new = _hashlib_new_replacement # type: ignore
