
import datetime
import os
from typing import Any, Optional
import unittest

# from bitcoinx import PublicKey

from electrumsv import contacts


pk_hex_1 = ("04d0de0aaeaefad02b8bdc8a01a1b8b11c696bd3d66a2c5f10780d95b7df42645cd85228a6fb29940e"+
    "858e7e55842ae2bd115d1ed7cc0e82d934e929c97648cb0a")
pk_hex_2 = '02edf5d63693c081edcc571187f219bb303022d0e83ac12b9c1ee803e7a7402312'

class TestContactExtras(unittest.TestCase):
    def test_contact_identity_persistence(self):
        for system_id in contacts.IdentitySystem:
            # We call 'astimezone' pre-emptively so that the comparison works.
            identity = contacts.ContactIdentity(os.urandom(32), system_id, "test",
                datetime.datetime.now().astimezone())
            data = identity.to_list()
            new_identity = contacts.ContactIdentity.from_list(data)
            self.assertEqual(identity, new_identity, str(data))

    def test_contact_entry_persistence(self):
        entry = contacts.ContactEntry(1, "zzz", [
            contacts.ContactIdentity(os.urandom(32), contacts.IdentitySystem.OnChain, "...", None)
        ])
        data = entry.to_list()
        new_entry = contacts.ContactEntry.from_list(data)
        self.assertEqual(entry, new_entry)

    def test_get_system_id(self):
        self.assertEqual(contacts.IdentitySystem.OnChain, contacts.get_system_id("onchain"))
        with self.assertRaises(contacts.ContactDataError):
            contacts.get_system_id("addressz")


class MockStorage(object):
    def __init__(self):
        self.d = {}

    def get(self, key: str, default: Optional[Any]=None) -> Any:
        return self.d.get(key, default)

    def put(self, key: str, value: Any) -> None:
        self.d[key] = value


class TestContacts(unittest.TestCase):
    def test_contacts_load(self):
        storage = MockStorage()
        c1 = contacts.Contacts(storage)
        self.assertEqual(0, len(c1._entries))

        c1.add_contact(contacts.IdentitySystem.OnChain, "name", pk_hex_1)
        self.assertEqual(1, len(c1._entries))

        c2 = contacts.Contacts(storage)
        self.assertEqual(1, len(c1._entries))

    def test_contacts_check_identity_exists(self):
        system_id = contacts.IdentitySystem.OnChain
        storage = MockStorage()
        c1 = contacts.Contacts(storage)
        c1.add_contact(system_id, "name", pk_hex_1)

        result = c1.check_identity_exists(system_id, pk_hex_1)
        self.assertEqual(contacts.IdentityCheckResult.InUse, result)

        result = c1.check_identity_exists(system_id, pk_hex_2)
        self.assertEqual(contacts.IdentityCheckResult.Ok, result)

    def test_contacts_check_identity_valid(self):
        system_id = contacts.IdentitySystem.OnChain
        storage = MockStorage()
        c1 = contacts.Contacts(storage)

        result = c1.check_identity_valid(system_id, pk_hex_1)
        self.assertEqual(contacts.IdentityCheckResult.Ok, result)

        result = c1.check_identity_valid(system_id, "...")
        self.assertEqual(contacts.IdentityCheckResult.Invalid, result)

        c1.add_contact(system_id, "name", pk_hex_1)

        result = c1.check_identity_exists(system_id, pk_hex_1)
        self.assertEqual(contacts.IdentityCheckResult.InUse, result)

    def test_contacts_check_label(self):
        system_id = contacts.IdentitySystem.OnChain
        storage = MockStorage()
        c1 = contacts.Contacts(storage)

        result = c1.check_label("")
        self.assertEqual(contacts.IdentityCheckResult.Invalid, result)

        result = c1.check_label("bob")
        self.assertEqual(contacts.IdentityCheckResult.Ok, result)

        c1.add_contact(system_id, "name", pk_hex_1)

        result = c1.check_label("name")
        self.assertEqual(contacts.IdentityCheckResult.InUse, result)

        result = c1.check_label("Name")
        self.assertEqual(contacts.IdentityCheckResult.InUse, result)

    def test_contacts_set_label(self):
        system_id = contacts.IdentitySystem.OnChain
        storage = MockStorage()
        contacts1 = contacts.Contacts(storage)
        entry1 = contacts1.add_contact(system_id, "name", pk_hex_1)

        contacts1.set_label(entry1.contact_id, "bob")

        entry2 = contacts1.get_contact(entry1.contact_id)
        self.assertEqual("bob", entry2.label)

    def test_contacts_contact_exists(self):
        storage = MockStorage()
        contacts1 = contacts.Contacts(storage)
        self.assertFalse(contacts1.contact_exists(1))

        system_id = contacts.IdentitySystem.OnChain
        contacts1.add_contact(system_id, "name", pk_hex_1)

        self.assertTrue(contacts1.contact_exists(1))

    def test_contacts_get_contact(self):
        system_id = contacts.IdentitySystem.OnChain
        storage = MockStorage()
        contacts1 = contacts.Contacts(storage)
        contact1_1 = contacts1.add_contact(system_id, "name", pk_hex_1)
        contact1_2 = contacts1.get_contact(contact1_1.contact_id)
        self.assertEqual(contact1_1, contact1_2)
        contacts1.set_label(contact1_1.contact_id, "bob")

        contact2 = contacts1.get_contact(contact1_1.contact_id)
        self.assertNotEqual(contact1_1, contact2)

    def test_contacts_get_contacts(self):
        system_id = contacts.IdentitySystem.OnChain
        storage = MockStorage()
        contacts1 = contacts.Contacts(storage)
        contact1 = contacts1.add_contact(system_id, "name1", pk_hex_1)
        contact2 = contacts1.add_contact(system_id, "name2", pk_hex_2)
        entries = contacts1.get_contacts()
        self.assertEqual(2, len(entries))
        self.assertEqual(set([ contact1.contact_id, contact2.contact_id ]),
            set([ c.contact_id for c in entries ]))

    def test_contacts_add_contact(self):
        storage = MockStorage()
        contacts1 = contacts.Contacts(storage)
        with self.assertRaises(contacts.ContactDataError):
            contacts1.add_contact(1000000, "name1", pk_hex_1)

        with self.assertRaises(contacts.ContactDataError):
            contacts1.add_contact(contacts.IdentitySystem.OnChain, "name1", "...")

        contact1 = contacts1.add_contact(contacts.IdentitySystem.OnChain, "name1", pk_hex_1)
        # Check that it got added.
        self.assertEqual(1, len(contacts1._entries))
        self.assertEqual(contact1, contacts1._entries[contact1.contact_id])

        # Check that what was added is what we expect.
        self.assertEqual(1, contact1.contact_id)
        self.assertEqual("name1", contact1.label)
        self.assertEqual(1, len(contact1.identities))
        self.assertEqual(contacts.IdentitySystem.OnChain, contact1.identities[0].system_id)
        self.assertEqual(pk_hex_1, contact1.identities[0].system_data)

    def test_contacts_remove_contact(self):
        storage = MockStorage()
        contacts1 = contacts.Contacts(storage)

        with self.assertRaises(KeyError):
            contacts1.remove_contact(10000)

        contact1 = contacts1.add_contact(contacts.IdentitySystem.OnChain, "name1", pk_hex_1)
        contacts1.remove_contact(contact1.contact_id)
        self.assertEqual(0, len(contacts1._entries))

    def test_contacts_remove_contacts(self):
        storage = MockStorage()
        contacts1 = contacts.Contacts(storage)
        contact1 = contacts1.add_contact(contacts.IdentitySystem.OnChain, "name1", pk_hex_1)
        contact2 = contacts1.add_contact(contacts.IdentitySystem.OnChain, "name2", pk_hex_2)
        self.assertEqual(2, len(contacts1._entries))

        contacts1.remove_contacts([ contact1.contact_id ])
        self.assertEqual(1, len(contacts1._entries))

        contacts1.remove_contacts([ 10000 ])
        self.assertEqual(1, len(contacts1._entries))

        contacts1.remove_contacts([ contact2.contact_id ])
        self.assertEqual(0, len(contacts1._entries))

        contact1 = contacts1.add_contact(contacts.IdentitySystem.OnChain, "name1", pk_hex_1)
        contact2 = contacts1.add_contact(contacts.IdentitySystem.OnChain, "name2", pk_hex_2)
        self.assertEqual(2, len(contacts1._entries))

        contacts1.remove_contacts([ contact1.contact_id, contact2.contact_id ])
        self.assertEqual(0, len(contacts1._entries))

    def test_contacts_add_identity(self):
        storage = MockStorage()
        contacts1 = contacts.Contacts(storage)
        contact1_1 = contacts1.add_contact(contacts.IdentitySystem.OnChain, "name1", pk_hex_1)
        contacts1.add_identity(contact1_1.contact_id, contacts.IdentitySystem.Paymail, "xxx")

        contact1_2 = contacts1.get_contact(contact1_1.contact_id)
        self.assertEqual(2, len(contact1_2.identities))

        system_ids = set([ v.system_id for v in contact1_2.identities ])
        expected_system_ids = set([
            contacts.IdentitySystem.OnChain, contacts.IdentitySystem.Paymail ])
        self.assertEqual(expected_system_ids, system_ids)

        identity1 = [
            v for v in contact1_2.identities if v.system_id == contacts.IdentitySystem.OnChain ][0]
        self.assertEqual(pk_hex_1, identity1.system_data)

        identity2 = [
            v for v in contact1_2.identities if v.system_id == contacts.IdentitySystem.Paymail ][0]
        self.assertEqual("xxx", identity2.system_data)

    def test_contacts_remove_identity(self):
        storage = MockStorage()
        contacts1 = contacts.Contacts(storage)
        contact1_1 = contacts1.add_contact(contacts.IdentitySystem.OnChain, "name1", pk_hex_1)
        identity1 = contact1_1.identities[0]
        identity2 = contacts1.add_identity(contact1_1.contact_id, contacts.IdentitySystem.Paymail, "xxx")
        self.assertEqual(2, len(contact1_1.identities))

        contact1_2 = contacts1.get_contact(contact1_1.contact_id)
        contacts1.remove_identity(contact1_2.contact_id, identity1.identity_id)
        self.assertEqual(1, len(contact1_2.identities))

        system_ids = set([ v.system_id for v in contact1_2.identities ])
        expected_system_ids = set([ contacts.IdentitySystem.Paymail ])
        self.assertEqual(expected_system_ids, system_ids)





