# Electrum - Lightweight Bitcoin Client
# Copyright (c) 2015 Thomas Voegtlin
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

import json

from .address import Address
from .dnssec import resolve_openalias
from .exceptions import FileImportFailed, FileImportFailedEncrypted
from .logs import logs

logger = logs.get_logger("contacts")


class Contacts(dict):

    def __init__(self, storage):
        super().__init__()

        self.storage = storage
        d = self.storage.get('contacts', {})
        try:
            self.update(d)
        except Exception:
            return
        # backward compatibility
        for k, v in self.items():
            _type, n = v
            if _type == 'address' and Address.is_valid(n):
                self.pop(k)
                self[n] = ('address', k)

    def save(self):
        self.storage.put('contacts', dict(self))

    def import_file(self, path):
        try:
            with open(path, 'r') as f:
                d = self._validate(json.loads(f.read()))
        except json.decoder.JSONDecodeError:
            logger.exception("importing file")
            raise FileImportFailedEncrypted()
        except BaseException:
            logger.exception("importing file")
            raise FileImportFailed()
        self.update(d)
        self.save()

    def __setitem__(self, key, value):
        dict.__setitem__(self, key, value)
        self.save()

    # This breaks expected dictionary pop behaviour.  In the normal
    # case, it'd return the popped value, or throw a KeyError.
    def pop(self, key):
        if key in self.keys():
            dict.pop(self, key)
            self.save()

    def resolve(self, k):
        if Address.is_valid(k):
            return {
                'address': Address.from_string(k),
                'type': 'address'
            }
        if k in self.keys():
            _type, addr = self[k]
            if _type == 'address':
                return {
                    'address': addr,
                    'type': 'contact'
                }
        out = resolve_openalias(k)
        if out:
            address, name, validated = out
            return {
                'address': address,
                'name': name,
                'type': 'openalias',
                'validated': validated
            }
        raise Exception("Invalid Bitcoin address or alias", k)

    def _validate(self, data):
        for k,v in list(data.items()):
            if k == 'contacts':
                return self._validate(v)
            if not Address.is_valid(k):
                data.pop(k)
            else:
                _type,_ = v
                if _type != 'address':
                    data.pop(k)
        return data
