# Open BSV License version 4
#
# Copyright (c) 2021,2022 Bitcoin Association for BSV ("Bitcoin Association")
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# 1 - The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# 2 - The Software, and any software that is derived from the Software or parts thereof,
# can only be used on the Bitcoin SV blockchains. The Bitcoin SV blockchains are defined,
# for purposes of this license, as the Bitcoin blockchain containing block height #556767
# with the hash "000000000000000001d956714215d96ffc00e0afda4cd0a96c96f8d802b1662b" and
# that contains the longest persistent chain of blocks accepted by this Software and which
# are valid under the rules set forth in the Bitcoin white paper (S. Nakamoto, Bitcoin: A
# Peer-to-Peer Electronic Cash System, posted online October 2008) and the latest version
# of this Software available in this repository or another repository designated by Bitcoin
# Association, as well as the test blockchains that contain the longest persistent chains
# of blocks accepted by this Software and which are valid under the rules set forth in the
# Bitcoin whitepaper (S. Nakamoto, Bitcoin: A Peer-to-Peer Electronic Cash System, posted
# online October 2008) and the latest version of this Software available in this repository,
# or another repository designated by Bitcoin Association
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

from __future__ import annotations
import asyncio
import dataclasses
from collections import defaultdict
from functools import partial
from typing import Callable, cast, TYPE_CHECKING

from bitcoinx import Chain, hash_to_hex_str, Header, MissingHeader

from ..app_state import app_state
from ..bitcoin import TSCMerkleProof, verify_proof
from ..constants import PendingHeaderWorkKind, TxFlags, WalletEvent
from ..logs import logs

if TYPE_CHECKING:
    from ..wallet import WalletDataAccess


logger = logs.get_logger("late-header-worker")

block_transactions_factory = cast(Callable[[], dict[bytes, set[bytes]]], partial(defaultdict, set))


@dataclasses.dataclass
class LateHeaderWorkerState:
    late_header_worker_queue: asyncio.Queue[tuple[PendingHeaderWorkKind,
        TSCMerkleProof | tuple[Header, Chain]]]
    block_transactions: dict[bytes, set[bytes]] = dataclasses.field(
        default_factory=block_transactions_factory)


async def late_header_worker_async(wallet_data: WalletDataAccess, state: LateHeaderWorkerState) \
        -> None:
    """
    We receive headers asynchronously and do not expect to have the headers before we
    receive data that needs to be processed. This worker matches deferred data processing
    to late header arrival.

    We need to respond to these events:
    - A new item is added to monitor. We should process it before tracking it to cover the
        gap between no header and in the list of those known to have no header.
    - A new header is received.
    """
    assert app_state.headers is not None

    for tx_hash, block_hash, proof_data in wallet_data.read_pending_header_transactions():
        # When we set the proof data on a transaction for deferred verification we also set the
        # block hash among other things. This is guaranteed to be set, so essential to check.
        assert block_hash is not None
        msg = (PendingHeaderWorkKind.MERKLE_PROOF, TSCMerkleProof.from_bytes(proof_data))
        state.late_header_worker_queue.put_nowait(msg)

    # TODO(1.4.0) Networking. Hook this up to arrival of new headers.

    while True:
        item_kind, item_any = await state.late_header_worker_queue.get()
        if item_kind == PendingHeaderWorkKind.MERKLE_PROOF:
            tsc_proof = cast(TSCMerkleProof, item_any)
            assert tsc_proof.block_hash is not None
            assert tsc_proof.transaction_hash is not None
            try:
                header, _chain = cast(tuple[Header, Chain],
                    app_state.headers.lookup(tsc_proof.block_hash))
            except MissingHeader:
                # We have confirmed that at this point the header is not present, monitor it.
                state.block_transactions[tsc_proof.block_hash].add(tsc_proof.transaction_hash)
            else:
                await _process_one_merkle_proof(wallet_data, state, tsc_proof.block_hash,
                    TxFlags.STATE_CLEARED, tsc_proof.transaction_hash, tsc_proof.to_bytes(), header)
        elif item_kind == PendingHeaderWorkKind.NEW_HEADER:
            header, _chain = cast(tuple[Header, Chain], item_any)
            if header.hash in state.block_transactions:
                tx_hashes = list(state.block_transactions[header.hash])
                unverified_entries = wallet_data.read_transaction_proof_data(tx_hashes)
                for proof_row in unverified_entries:
                    assert proof_row.block_hash is not None
                    assert proof_row.proof_bytes is not None
                    await _process_one_merkle_proof(wallet_data, state, proof_row.tx_hash,
                        proof_row.flags, proof_row.block_hash, proof_row.proof_bytes, header)
                del state.block_transactions[header.hash]
        else:
            raise NotImplementedError(f"Unknown late header work item kind {item_kind}")


async def _process_one_merkle_proof(wallet_data: WalletDataAccess,
        state: LateHeaderWorkerState, tx_hash: bytes, flags: TxFlags, tx_block_hash: bytes,
        proof_data: bytes, header: Header) -> None:
    # It is possible that the transaction may have changed from under us in the database,
    # we need to check that it hasn't, but if it has skip the transaction.
    if proof_data is None:
        logger.error("Deferred verification transaction %s block hash now lacks proof data",
            hash_to_hex_str(tx_hash))
        return

    if flags & TxFlags.MASK_STATE != TxFlags.STATE_CLEARED:
        logger.error("Deferred verification transaction %s state unexpectedly changed "
                     "from %r to %r", hash_to_hex_str(tx_hash), TxFlags.STATE_CLEARED,
            TxFlags(flags))
        return

    if tx_block_hash != header.hash:
        logger.error("Deferred verification transaction %s block hash unexpectedly changed "
                     "from %s to %s", hash_to_hex_str(tx_hash), hash_to_hex_str(header.hash),
            hash_to_hex_str(tx_block_hash))
        return

    tsc_proof = TSCMerkleProof.from_bytes(proof_data)
    if verify_proof(tsc_proof, header.merkle_root):
        # TODO(1.4.0) Database consistency. This should be a database call that checks the
        #     transaction is still in the state where it needs processing, and if it is not, then
        #     we log an error and move on.
        if await wallet_data.update_transaction_flags_async(tx_hash, TxFlags.STATE_SETTLED,
                TxFlags.MASK_STATELESS):
            wallet_data.events.trigger_callback(WalletEvent.TRANSACTION_VERIFIED, tx_hash, header,
                tsc_proof)
        else:
            logger.error("Deferred verification failed updating transaction %s state "
                "from %r to %r", hash_to_hex_str(tx_hash), TxFlags(flags), TxFlags.STATE_SETTLED)
    else:
        # TODO(bad-server)
        # TODO(1.4.0) Networking. We probably want to know what server this came from so we can
        #    treat it as a bad server. And we would want to retry with a good server.
        logger.error("Deferred verification transaction %s failed verifying proof",
            hash_to_hex_str(tx_hash))
        # Remove the "pending verification" proof and block data from the transaction, it
        # should not be necessary to update the UI as the transaction should not have
        # changed state and we do not display "pending verification" proofs.
        await wallet_data.update_transaction_proof_async(tx_hash, None, None, None,
            TxFlags.STATE_CLEARED)
