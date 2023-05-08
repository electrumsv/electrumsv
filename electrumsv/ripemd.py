import hashlib
from typing import Any

_hashlib_new_original: Any = None
_hashlib_new_reference: Any = None

def _hashlib_new_replacement(hasher_name: str, *args, **kwargs) -> Any:
    global _hashlib_new_original, _hashlib_new_reference
    if hasher_name == "ripemd160":
        if _hashlib_new_reference is None:
            from Cryptodome.Hash import RIPEMD160
            _hashlib_new_reference = RIPEMD160.new
        return _hashlib_new_reference(*args, **kwargs)
    return _hashlib_new_original(hasher_name, *args, **kwargs)

if _hashlib_new_original is None:
    _hashlib_new_original = hashlib.new
# NOTE(typing) The `hashlib.new` typing is too complicated to bother replicating.
hashlib.new = _hashlib_new_replacement # type: ignore
