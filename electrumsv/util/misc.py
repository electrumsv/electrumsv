from collections import deque
from itertools import chain
import os
import platform
from sys import getsizeof
import subprocess
from typing import Any, Generator
import uuid

from bitcoinx import Script

from electrumsv.constants import ScriptType
from electrumsv.transaction import Transaction, XTxInput, XTxOutput, XPublicKey


def obj_size(o: Any) -> int:
    """This is a modified version of: https://code.activestate.com/recipes/577504/
    to suit our bitcoin-specific needs

    Returns the approximate memory footprint of an object and all of its contents.

    Automatically finds the contents of the following builtin containers and
    their subclasses:  tuple, list, deque, dict, set.

    Additionally calculates the size of:
    - electrumsv.transaction.Transaction
    - electrumsv.transaction.XPublicKey - approximation based on their serialized bytes footprint
    - electrumsv.transaction.XTxInput
    - electrumsv.transaction.XTxOutput
    - electrumsv.constants.ScriptType
    - bitcoinx.Script
    """
    dict_handler = lambda d: chain.from_iterable(d.items())

    def attrs_object_iterator(obj: Any) -> Generator[Any, None, None]:
        """This is for iterating over attributes on classes produced via the 3rd
        party library "attrs"""
        return (getattr(obj, field.name) for field in obj.__attrs_attrs__)

    all_handlers = {
        tuple: iter,
        list: iter,
        deque: iter,
        dict: dict_handler,
        set: iter,
        Transaction: attrs_object_iterator,
        XTxInput: attrs_object_iterator,
        XTxOutput: attrs_object_iterator}

    seen = set()  # track which object id's have already been seen
    default_size = getsizeof(0)  # estimate sizeof object without __sizeof__

    def sizeof(o: Any) -> int:
        if id(o) in seen:  # do not double count the same object
            return 0
        seen.add(id(o))
        s = getsizeof(o, default_size)

        if isinstance(o, Script):
            s = len(o)

        if isinstance(o, ScriptType):
            s = 28

        if isinstance(o, XPublicKey):
            s = len(o.to_bytes())  # easiest approximation

        for typ, handler in all_handlers.items():
            if isinstance(o, typ):
                s += sum(map(sizeof, handler(o)))
                break

        return s

    return sizeof(o)


class ProgressCallbacks:
    def set_stage_count(self, stages: int) -> None:
        pass

    def begin_stage(self, stage_id: int) -> None:
        pass

    def progress(self, progress: int, message: str) -> None:
        pass


UNKNOWN_UUID = uuid.UUID(hex="FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF")


def get_linux_system_uuid() -> uuid.UUID:
    if os.path.isfile("/etc/machine-id"):
        with open("/etc/machine-id", "r") as f:
            return uuid.UUID(bytes=bytes.fromhex(f.read()))
    return UNKNOWN_UUID


def get_macos_system_uuid() -> uuid.UUID:
    try:
        output_bytes = subprocess.check_output("ioreg -rd1 -c IOPlatformExpertDevice".split())
    except subprocess.CalledProcessError:
        return UNKNOWN_UUID

    for line in [ s.strip() for s in output_bytes.decode().split("\n") if len(s) ]:
        if line.startswith("\"IOPlatformUUID\""):
            key, value = line.split(" = ", 1)
            uuid_hex = value.strip()[1:-1]
            return uuid.UUID(hex=uuid_hex)
    # It is not expected that this will happen on MacOS.
    return UNKNOWN_UUID


def get_windows_system_uuid() -> uuid.UUID:
    # TODO(windows-store) Is this available in APPX containers?
    output_bytes = subprocess.check_output('wmic csproduct get uuid')
    machine_id = output_bytes.decode().split('\n')[1].strip()
    machine_uuid = uuid.UUID(hex=machine_id)
    if machine_uuid != UNKNOWN_UUID:
        return machine_uuid
    # TODO(rt12) This is apparently a possibility for some systems.
    return UNKNOWN_UUID


def get_system_uuid() -> uuid.UUID:
    system_name = platform.system()
    if system_name == "Windows":
        return get_windows_system_uuid()
    elif system_name == "Darwin":
        return get_macos_system_uuid()
    else:
        return get_linux_system_uuid()
