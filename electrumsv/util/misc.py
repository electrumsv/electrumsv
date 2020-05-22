from collections import deque
from itertools import chain
from sys import getsizeof

import bitcoinx

from electrumsv.constants import ScriptType
from electrumsv.transaction import Transaction, XTxInput, XTxOutput, XPublicKey


def obj_size(o):
    """This is a modified version of: https://code.activestate.com/recipes/577504/
    to suit our bitcoin-specific needs

    Returns the approximate memory footprint of an object and all of its contents.

    Automatically finds the contents of the following builtin containers and
    their subclasses:  tuple, list, deque, dict, set.

    Additionally calculates the size of:
    - electrumsv.transaction.Transaction
    - electrumsv.transaction.XTxInput
    - electrumsv.transaction.XTxOutput
    - electrumsv.constants.ScriptType
    - bitcoinx.Script
    - bitcoinx.XPublicKey - approximation based on their serialized bytes footprint
    """
    dict_handler = lambda d: chain.from_iterable(d.items())

    def attrs_object_iterator(obj):
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

    def sizeof(o):

        if id(o) in seen:  # do not double count the same object
            return 0
        seen.add(id(o))
        s = getsizeof(o, default_size)

        if isinstance(o, bitcoinx.Script):
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