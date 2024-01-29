from __future__ import annotations
import io, json, os, struct
from typing import cast

from bitcoinx import hash_to_hex_str, pack_varbytes, pack_varint, \
    read_varbytes, read_varint

from ..constants import AccountFlag, AccountPaymentFlag, DerivationType, KeyInstanceFlag, \
    MasterKeyFlag, NO_BLOCK_HASH, ScriptType, TxFlag, TXOFlag
from ..types import BackupWritingProtocol, ChunkState, MasterKeyDataBIP32
from ..wallet_database.types import AccountRow, AccountPaymentRow, KeyInstanceRow, \
    MasterKeyRow, PaymentRow, TransactionInputRow, TransactionOutputRow, TransactionRow


class BACKUP_IDS:
    HEADER              = b"H_______"
    MASTERKEY           = b"MK______"
    ACCOUNT             = b"ACC_____"
    ACCOUNT_PAYMENT     = b"ACCPMT__"
    PAYMENT             = b"PMT_____"
    TRANSACTION         = b"TX______"
    TRANSACTION_INPUT   = b"TXI_____"
    TRANSACTION_OUTPUT  = b"TXO_____"
    KEYINSTANCES        = b"K+______"

BACKUP_VERSIONS: dict[bytes, int] = {
    BACKUP_IDS.HEADER:               1,
    BACKUP_IDS.MASTERKEY:            1,
    BACKUP_IDS.ACCOUNT:              1,
    BACKUP_IDS.ACCOUNT_PAYMENT:      1,
    BACKUP_IDS.PAYMENT:              1,
    BACKUP_IDS.TRANSACTION:          1,
    BACKUP_IDS.TRANSACTION_INPUT:    1,
    BACKUP_IDS.TRANSACTION_OUTPUT:   1,
    BACKUP_IDS.KEYINSTANCES:         1,
}


# @BackupPhilosophy
# Just map the database contents directly into the backup data format. Do no processing to save
# space.

size_struct = struct.Struct("<Q")

def write_chunk_start(stream: io.BytesIO, chunk_id: bytes) -> ChunkState:
    stream.write(chunk_id)
    stream.write(int.to_bytes(BACKUP_VERSIONS[chunk_id], length=1, byteorder="little"))
    length_offset = stream.tell()
    stream.write(size_struct.pack(0)) # Placeholder chunk size value.
    return ChunkState(length_offset)

def write_chunk_end(stream: io.BytesIO, state: ChunkState) -> None:
    next_offset = stream.tell()
    stream.seek(state.length_offset, os.SEEK_SET)
    stream.write(size_struct.pack(0)) # Replacement chunk size value.
    stream.seek(next_offset, os.SEEK_SET)


HEADER_STRUCT = struct.Struct("<I")

def read_backup_header_from_stream(stream: io.BytesIO) -> int:
    migration_version: int
    migration_version, = HEADER_STRUCT.unpack(stream.read(HEADER_STRUCT.size))
    return migration_version

def write_backup_header_to_stream(stream: io.BytesIO, db_migration: int) -> None:
    stream.write(HEADER_STRUCT.pack(db_migration))

def read_masterkey_from_stream(stream: io.BytesIO) -> MasterKeyRow:
    t = struct.unpack("<QQHIII", stream.read(struct.calcsize("<QQHIII")))
    masterkey_id = t[0]
    parent_masterkey_id = None if t[1] == 0 else t[0]
    derivation_type = DerivationType(t[2])
    masterkey_flags = MasterKeyFlag(t[3])
    date_created = t[4]
    date_updated = t[4]

    # MAY support hardware wallets later.
    # WILL support multi-signature wallets later.
    # WILL NOT support old Electrum seeds.
    if derivation_type != DerivationType.BIP32:
        raise ValueError(f"Backup not supported for '{derivation_type}' masterkeys")

    derivation_data: MasterKeyDataBIP32 = {
        "derivation":   None,
        "label":        None,
        "passphrase":   None,
        "seed":         None,
        "xprv":         None,
        "xpub":         read_varbytes(stream.read).decode(),
    }
    field_value = read_varbytes(stream.read)
    derivation_data["seed"] = None if field_value == b"" else field_value.decode()
    field_value = read_varbytes(stream.read)
    derivation_data["xprv"] = None if field_value == b"" else field_value.decode()
    field_value = read_varbytes(stream.read)
    derivation_data["passphrase"] = None if field_value == b"" else field_value.decode()
    field_value = read_varbytes(stream.read)
    derivation_data["derivation"] = None if field_value == b"" else field_value.decode()
    field_value = read_varbytes(stream.read)
    derivation_data["label"] = None if field_value == b"" else field_value.decode()
    return MasterKeyRow(masterkey_id, parent_masterkey_id, derivation_type,
        json.dumps(derivation_data).encode(), masterkey_flags, date_created, date_updated)

def write_masterkey_to_stream(stream: io.BytesIO, row: MasterKeyRow) -> None:
    stream.write(struct.pack("<QQHIII", row.masterkey_id, row.parent_masterkey_id
        if row.parent_masterkey_id is not None else 0, row.derivation_type,
        row.flags, row.date_created, row.date_updated))

    # MAY support hardware wallets later.
    # WILL support multi-signature wallets later.
    # WILL NOT support old Electrum seeds.
    if row.derivation_type != DerivationType.BIP32:
        raise ValueError(f"Backup not supported for '{row.derivation_type}' masterkeys")

    # - If only xpub is set it is an imported extended public key.
    # - If only xpub and xprv are set it is an imported extended private key.
    # - If seed, xprv, xpub are set will either be an Electrum seed or BIP39 seed.
    #   For newer entries, derivation may be set with 'm' and/or a flag indicating an
    #   Electrum seed. Or a custom derivation path and/or a flag indicating a BIP39
    #   seed.
    # * Label might only have been used for hardware wallets??
    derivation_data = cast(MasterKeyDataBIP32, json.loads(row.derivation_data))
    stream.write(pack_varbytes(derivation_data["xpub"].encode()))
    stream.write(pack_varbytes(derivation_data["seed"].encode())
        if derivation_data["seed"] is not None else b"")
    stream.write(pack_varbytes(derivation_data["xprv"].encode())
        if derivation_data["xprv"] is not None else b"")
    stream.write(pack_varbytes(derivation_data["passphrase"].encode())
        if derivation_data["passphrase"] is not None else b"")
    stream.write(pack_varbytes(derivation_data["derivation"].encode())
        if derivation_data["derivation"] is not None else b"")
    stream.write(pack_varbytes(derivation_data["label"].encode()
        if derivation_data["label"] is not None else b""))

ACCOUNT_STRUCT = struct.Struct("<QQHIQQQQII")

def read_account_from_stream(stream: io.BytesIO) -> AccountRow:
    t = ACCOUNT_STRUCT.unpack(stream.read(ACCOUNT_STRUCT.size))
    account_name = read_varbytes(stream.read)
    return AccountRow(t[0], None if t[1] == 0 else t[1], ScriptType(t[2]), account_name,
        AccountFlag(t[3]), None if t[4] == 0 else t[4], None if t[5] == 0 else t[5],
        None if t[6] == 0 else t[6], None if t[7] == 0 else t[7], t[8], t[9])

def write_account_to_stream(stream: io.BytesIO, row: AccountRow) -> None:
    stream.write(ACCOUNT_STRUCT.pack(row.account_id,
        row.default_masterkey_id if row.default_masterkey_id is not None else 0,
        row.default_script_type, row.flags,
        row.blockchain_server_id if row.blockchain_server_id is not None else 0,
        row.peer_channel_server_id if row.peer_channel_server_id is not None else 0,
        row.bitcache_channel_id if row.bitcache_channel_id is not None else 0,
        row.external_bitcache_channel_id if row.external_bitcache_channel_id is not None else 0,
        row.date_created, row.date_updated))
    stream.write(pack_varbytes(row.account_name.encode()))

PAYMENT_STRUCT = struct.Struct("<QQIII")

def read_payment_from_stream(stream: io.BytesIO) -> tuple[PaymentRow, list[AccountPaymentRow]]:
    payment_id, contact_id, flags, date_created, date_updated = \
        PAYMENT_STRUCT.unpack(stream.read(PAYMENT_STRUCT.size))
    link_count = read_varint(stream.read)
    account_payment_rows: list[AccountPaymentRow] = [ read_account_payment_from_stream(stream)
        for i in range(link_count) ]
    return PaymentRow(payment_id, None if contact_id == 0 else contact_id, flags, date_created,
        date_updated), account_payment_rows

def write_payment_to_stream(stream: io.BytesIO, row: PaymentRow,
        link_rows: list[AccountPaymentRow]) -> None:
    stream.write(PAYMENT_STRUCT.pack(row.payment_id, row.contact_id
        if row.contact_id is not None else 0, row.flags, row.date_created, row.date_updated))
    stream.write(pack_varint(len(link_rows)))
    for link_row in link_rows: write_account_payment_to_stream(stream, link_row)

AP_STRUCT = struct.Struct("<QQIII")

def read_account_payment_from_stream(stream: io.BytesIO) -> AccountPaymentRow:
    t = AP_STRUCT.unpack(stream.read(AP_STRUCT.size))
    return AccountPaymentRow(t[0], t[1], AccountPaymentFlag(t[2]), t[3], t[4])

def write_account_payment_to_stream(stream: io.BytesIO, row: AccountPaymentRow) -> None:
    stream.write(AP_STRUCT.pack(row.account_id, row.payment_id, row.flags, row.date_created,
        row.date_updated))

TX_STRUCT = struct.Struct("<32sI32siIIIIcIII")

def read_transaction_from_stream(stream: io.BytesIO) -> tuple[TransactionRow,
        list[TransactionInputRow], list[TransactionOutputRow], list[KeyInstanceRow]]:
    t = TX_STRUCT.unpack(stream.read(TX_STRUCT.size))
    tx_bytes = read_varbytes(stream.read)
    input_count = read_varint(stream.read)
    input_rows = [ read_transaction_input_from_stream(stream) for i in range(input_count) ]
    output_count = read_varint(stream.read)
    output_rows = [ read_transaction_output_from_stream(stream) for i in range(output_count) ]
    key_rows = read_keyinstances_from_stream(stream)
    value_mask = t[8] # Deal with `None` values that can have a `0` value.
    return TransactionRow(t[0], tx_bytes, TxFlag(t[1]), None if t[2] == NO_BLOCK_HASH else t[2],
        t[3], t[4] if value_mask & 1<<0 else None, t[5] if value_mask & 1<<1 else None,
        t[6] if value_mask & 1<<2 else None, t[7] if value_mask & 1<<3 else None,
        None if t[9] == 0 else t[9], t[10], t[11]), input_rows, output_rows, key_rows

def write_transaction_to_stream(stream: io.BytesIO, row: TransactionRow,
        input_rows: list[TransactionInputRow], output_rows: list[TransactionOutputRow],
        key_rows: list[KeyInstanceRow]) -> None:
    if row.tx_bytes is None: raise ValueError(f"Tx {hash_to_hex_str(row.tx_hash)} lacks byte data")
    value_mask = 0 # Deal with `None` values that can have a `0` value.
    if row.block_position is not None:  value_mask |= 1<<0
    if row.fee_value is not None:       value_mask |= 1<<1
    if row.version is not None:         value_mask |= 1<<2
    if row.locktime is not None:        value_mask |= 1<<3
    stream.write(TX_STRUCT.pack(row.tx_hash, row.flags,
        NO_BLOCK_HASH if row.block_hash is None else row.block_hash, row.block_height,
        # These fields can have a `None` value which may be 0, the otherwise usual placeholder.
        row.block_position, row.fee_value, row.version, row.locktime, value_mask,
        0 if row.payment_id is None else row.payment_id, row.date_created, row.date_updated))
    stream.write(pack_varbytes(row.tx_bytes))
    stream.write(pack_varint(len(input_rows)))
    for input_row in input_rows: write_transaction_input_to_stream(stream, input_row)
    stream.write(pack_varint(len(output_rows)))
    for output_row in output_rows: write_transaction_output_to_stream(stream, output_row)
    write_keyinstances_to_stream(stream, key_rows)

TXI_STRUCT = struct.Struct("<32sI32sIIIIIII")

def read_transaction_input_from_stream(stream: io.BytesIO) -> TransactionInputRow:
    return TransactionInputRow(*TXI_STRUCT.unpack(stream.read(TXI_STRUCT.size)))

def write_transaction_input_to_stream(stream: io.BytesIO, row: TransactionInputRow) -> None:
    stream.write(TXI_STRUCT.pack(row.tx_hash, row.txi_index, row.spent_tx_hash,
        row.spent_txo_index, row.sequence, row.flags, row.script_offset, row.script_length,
        row.date_created, row.date_updated))

TXO_STRUCT = struct.Struct("<32sIIIIIIIII")

def read_transaction_output_from_stream(stream: io.BytesIO) -> TransactionOutputRow:
    t = TXO_STRUCT.unpack(stream.read(TXO_STRUCT.size))
    return TransactionOutputRow(t[0], t[1], t[2], None if t[3] == 0 else t[3], ScriptType(t[4]),
        TXOFlag(t[5]), t[6], t[7], t[8], t[9])

def write_transaction_output_to_stream(stream: io.BytesIO, row: TransactionOutputRow) -> None:
    stream.write(TXO_STRUCT.pack(row.tx_hash, row.txo_index, row.value,
        0 if row.keyinstance_id is None else row.keyinstance_id, row.script_type, row.flags,
        row.script_offset, row.script_length, row.date_created, row.date_updated))

KEY_STRUCT = struct.Struct("<QQIII")

def read_keyinstances_from_stream(stream: io.BytesIO) -> list[KeyInstanceRow]:
    t = KEY_STRUCT.unpack(stream.read(KEY_STRUCT.size))
    key_count = read_varint(stream.read)
    result: list[KeyInstanceRow] = []
    for i in range(key_count):
        derivation_type = DerivationType(t[3])
        derivation_data = read_varbytes(stream.read) # @DerivationDataContents
        derivation_data2 = read_varbytes(stream.read)
        if derivation_type not in (DerivationType.BIP32_SUBPATH, DerivationType.PRIVATE_KEY,
                DerivationType.PUBLIC_KEY_HASH, DerivationType.SCRIPT_HASH):
            raise ValueError(f"Unsupported derivation type {t[0]}:{derivation_type}")
        description = read_varbytes(stream.read).decode()
        result.append(KeyInstanceRow(t[0], t[1], None if t[2] == 0 else t[2], derivation_type,
            derivation_data, derivation_data2, KeyInstanceFlag(t[4]),
            None if description == "" else description))
    return result

def write_keyinstances_to_stream(stream: io.BytesIO, rows: list[KeyInstanceRow]) -> None:
    stream.write(pack_varint(len(rows)))
    for row in rows:
        stream.write(KEY_STRUCT.pack(row.keyinstance_id, row.account_id,
            0 if row.masterkey_id is None else row.masterkey_id, row.derivation_type,
            row.flags))
        stream.write(pack_varbytes(row.derivation_data)) # @DerivationDataContents
        assert row.derivation_data2 is not None
        stream.write(pack_varbytes(row.derivation_data2))
        if row.derivation_type not in (DerivationType.BIP32_SUBPATH, DerivationType.PRIVATE_KEY,
                DerivationType.PUBLIC_KEY_HASH, DerivationType.SCRIPT_HASH):
            raise ValueError(
                f"Unsupported derivation type {row.keyinstance_id}:{row.derivation_type}")
        stream.write(pack_varbytes(b"" if row.description is None else row.description.encode()))


class BackupWriter(BackupWritingProtocol):
    write_chunk_start = staticmethod(write_chunk_start)
    write_chunk_end = staticmethod(write_chunk_end)
    write_backup_header_to_stream = staticmethod(write_backup_header_to_stream)
    write_masterkey_to_stream = staticmethod(write_masterkey_to_stream)
    write_account_to_stream = staticmethod(write_account_to_stream)
    write_payment_to_stream = staticmethod(write_payment_to_stream)
    write_account_payment_to_stream = staticmethod(write_account_payment_to_stream)
    write_transaction_to_stream = staticmethod(write_transaction_to_stream)
    write_transaction_input_to_stream = staticmethod(write_transaction_input_to_stream)
    write_transaction_output_to_stream = staticmethod(write_transaction_output_to_stream)
    write_keyinstances_to_stream = staticmethod(write_keyinstances_to_stream)
