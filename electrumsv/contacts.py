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

import datetime
from dateutil.parser import isoparse
from enum import IntEnum
from typing import Any, Iterable, List, NamedTuple, Optional, Tuple

from bitcoinx import PublicKey, sha256

from .logs import logs


logger = logs.get_logger("contacts")


class IdentityCheckResult(IntEnum):
    Ok = 1
    Invalid = 2
    InUse = 3


class IdentitySystem(IntEnum):
    OnChain = 1
    Paymail = 2


IDENTITY_SYSTEM_NAMES = {
    IdentitySystem.OnChain: "OnChain",
    IdentitySystem.Paymail: "Paymail",
}


class ContactDataError(Exception):
    pass


class ContactNotFoundError(Exception):
    pass


def get_system_id(system_name: str) -> IdentitySystem:
    system_name = system_name.strip().lower()
    for k, v in IDENTITY_SYSTEM_NAMES.items():
        if v.lower() == system_name:
            return k
    raise ContactDataError(f"Unknown system name {system_name}")


class ContactIdentity(NamedTuple):
    identity_id: bytes
    system_id: IdentitySystem
    system_data: Any
    last_verified: Optional[datetime.datetime] = None

    def to_list(self) -> List[Any]:
        return [
            self.identity_id.hex(),
            int(self.system_id),
            self.system_data,
            self.last_verified.astimezone().isoformat()
                if self.last_verified is not None else None,
        ]

    @classmethod
    def from_list(klass, data: List) -> "ContactIdentity":
        dt = None
        if data[3] is not None:
            dt = isoparse(data[3])
        return klass(bytes.fromhex(data[0]), IdentitySystem(data[1]), data[2], dt)


class ContactEntry(NamedTuple):
    contact_id: int
    label: str
    identities: Iterable[ContactIdentity]

    def to_list(self) -> List[Any]:
        return [ self.contact_id, self.label, [ each.to_list() for each in self.identities ] ]

    @classmethod
    def from_list(klass, data: List) -> "ContactEntry":
        identities = [ ContactIdentity.from_list(l) for l in data[2] ]
        return klass(data[0], data[1], identities)


class Contacts(object):
    def __init__(self, storage):
        self._identity_contact_id = {}
        self._entries = {}
        self.storage = storage

        data = storage.get('contacts2')
        if data is not None:
            version, contacts_data = data
            if version < 4:
                pass
            elif version == 4:
                for row in contacts_data:
                    entry = ContactEntry.from_list(row)
                    self._entries[entry.contact_id] = entry

                    for identity in entry.identities:
                        self._identity_contact_id[identity.identity_id] = entry.contact_id

            else:
                raise ContactDataError("Unrecognized version")

    def save(self):
        contacts_data = []
        for entry in self._entries.values():
            contacts_data.append(entry.to_list())
        self.storage.put('contacts2', [ 4, contacts_data ])

    def check_identity_exists(self, system_id: IdentitySystem,
            system_data: Any) -> IdentityCheckResult:
        for entry in self._entries.values():
            for identity in entry.identities:
                if identity.system_id == system_id and identity.system_data == system_data:
                    return IdentityCheckResult.InUse
        return IdentityCheckResult.Ok

    def check_identity_valid(self, system_id: IdentitySystem, system_data: Any,
            skip_exists: Optional[bool]=False) -> IdentityCheckResult:
        if system_id == IdentitySystem.OnChain:
            if self._is_public_key_valid(system_data):
                if skip_exists:
                    return IdentityCheckResult.Ok
                return self.check_identity_exists(system_id, system_data)
        return IdentityCheckResult.Invalid

    def check_label(self, label: str) -> IdentityCheckResult:
        label = label.strip().lower()
        if not len(label):
            return IdentityCheckResult.Invalid
        for entry in self._entries.values():
            if label == entry.label.lower():
                return IdentityCheckResult.InUse
        return IdentityCheckResult.Ok

    def set_label(self, contact_id: int, label: str) -> None:
        old_contact = self._entries[contact_id]
        new_contact = ContactEntry(contact_id, label, old_contact.identities)
        self._entries[contact_id] = new_contact
        self.save()

    def contact_exists(self, contact_id: int) -> bool:
        return contact_id in self._entries

    def get_contact(self, contact_id: int) -> Optional[ContactEntry]:
        return self._entries.get(contact_id, None)

    def get_contacts(self) -> Iterable[ContactEntry]:
        return self._entries.values()

    def get_contact_identities(self) -> Iterable[Tuple[ContactEntry, ContactIdentity]]:
        results = []
        for contact in self._entries.values():
            for identity in contact.identities:
                results.append((contact, identity))
        return results

    def add_contact(self, system_id: IdentitySystem, label: str,
            identity_data: Any) -> ContactEntry:
        try:
            IdentitySystem(system_id)
        except ValueError:
            raise ContactDataError("Identity system unknown")

        if self.check_identity_valid(system_id, identity_data,
                skip_exists=True) == IdentityCheckResult.Invalid:
            raise ContactDataError("Identity is not valid")

        contact_id = 1
        if len(self._entries):
            contact_id = max(k for k in self._entries.keys()) + 1
        identity_id = self._get_unique_identity_id(system_id, identity_data)
        identity = ContactIdentity(identity_id, system_id, identity_data)
        contact = self._entries[contact_id] = ContactEntry(contact_id, label, [ identity ])
        self.save()

        self._on_contact_added(contact, identity)

        return self._entries[contact_id]

    def remove_contact(self, contact_id: int) -> None:
        if contact_id not in self._entries:
            raise KeyError(contact_id)
        contact = self._entries[contact_id]
        del self._entries[contact_id]
        self.save()

        self._on_contact_removed(contact)

    def remove_contacts(self, contact_ids: Iterable[int]) -> None:
        changed = False
        removed = []
        for contact_id in contact_ids:
            if contact_id in self._entries:
                removed.append(self._entries[contact_id])
                del self._entries[contact_id]
                changed = True
        if changed:
            self.save()

        for contact in removed:
            self._on_contact_removed(contact)

    def add_identity(self, contact_id: int, system_id: IdentitySystem, system_data: str) \
            -> ContactIdentity:
        contact = self._entries[contact_id]
        identity_id = self._get_unique_identity_id(system_id, system_data)
        identity = ContactIdentity(identity_id, system_id, system_data)
        contact.identities.append(identity)
        self.save()

        self._on_identity_added(contact, identity)

        return identity

    def remove_identity(self, contact_id: int, identity_id: int) -> None:
        contact = self._entries[contact_id]
        for identity in contact.identities:
            if identity.identity_id == identity_id:
                contact.identities.remove(identity)
                self.save()

                self._on_identity_removed(contact, identity)
                break

    def _get_unique_identity_id(self, system_id: IdentitySystem, system_data: str) -> bytes:
        if system_id == IdentitySystem.OnChain:
            return bytes.fromhex(system_data)
        return sha256(system_data.encode('utf-8'))

    def _is_public_key_valid(self, hex: str) -> bool:
        try:
            PublicKey.from_hex(hex)
            return True
        except (ValueError, TypeError):
            # ValueError <- PublicKey.from_hex()
            # TypeError <- PublicKey()
            return False

    def _on_identity_added(self, contact: ContactEntry, identity: ContactIdentity) -> None:
        pass

    def _on_identity_removed(self, contact: ContactEntry, identity: ContactIdentity) -> None:
        pass

    def _on_contact_added(self, contact: ContactEntry, identity: ContactIdentity) -> None:
        pass

    def _on_contact_removed(self, contact: ContactEntry) -> None:
        pass

