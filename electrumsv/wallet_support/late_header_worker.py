
from __future__ import annotations
import asyncio
import dataclasses
from typing import Callable, cast, Tuple, Union
import weakref

from bitcoinx import Chain, hash_to_hex_str, Header, MissingHeader

from ..app_state import app_state
from ..bitcoin import TSCMerkleProof, verify_proof
from ..constants import PendingHeaderWorkKind, TxFlags
from ..logs import logs
from ..wallet_database.functions import AsynchronousFunctions


logger = logs.get_logger("late-header-worker")


@dataclasses.dataclass
class LateHeaderWorkerState:
    queue: asyncio.Queue[Tuple[PendingHeaderWorkKind, Union[TSCMerkleProof, Tuple[Header, Chain]]]]
    verification_callback: weakref.WeakMethod[Callable[[str, bytes, Header, TSCMerkleProof], None]]
    block_transactions: dict[bytes, set[bytes]] = dataclasses.field(default_factory=dict)



async def late_header_worker_async(db_functions_async: AsynchronousFunctions,
        state: LateHeaderWorkerState) -> None:
    """
    We receive headers asynchronously and do not expect to have the headers before we
    receive data that needs to be processed. This worker matches deferred data processing
    to late header arrival.

    We need to respond to these events:
    - A new item is added to monitor. We should process it before tracking it to cover the
        gap between no header and in the list of those known to have no header.
    - A new header is received.
    """
    # TODO(1.4.0): Read in any cleared transactions with proofs. These are expected to be
    #     ones that we did not have the header for. Put them in the queue (with no wait).
    await _populate_initial_state(db_functions_async, state)

    # TODO(1.4.0): Hook this up to arrival of new headers.

    while True:
        await _process_one_item(db_functions_async, state)


async def _populate_initial_state(db_functions_async: AsynchronousFunctions,
        state: LateHeaderWorkerState) -> None:
    rows = await db_functions_async.read_pending_header_transactions_async()
    for tx_hash, block_hash in rows:
        # When we set the proof data on a transaction for deferred verication we also set the
        # block hash among other things. This is guaranteed to be set, so essential to check.
        assert block_hash is not None
        if block_hash not in state.block_transactions:
            state.block_transactions[block_hash] = { tx_hash }
        else:
            state.block_transactions[block_hash].add(tx_hash)


async def _process_one_item(db_functions_async: AsynchronousFunctions,
        state: LateHeaderWorkerState) -> None:
    """
    Take one item from the work queue and process it, if there are no pending items, block until
    there is.
    """
    item_kind, item_any = await state.queue.get()
    if item_kind == PendingHeaderWorkKind.MERKLE_PROOF:
        tsc_proof = cast(TSCMerkleProof, item_any)
        await _process_merkle_proof(db_functions_async, state, tsc_proof)
    elif item_kind == PendingHeaderWorkKind.NEW_HEADER:
        header, chain = cast(Tuple[Header, Chain], item_any)
        await _process_header(db_functions_async, state, header, chain)
    else:
        raise NotImplementedError(f"Unknown late header work item kind {item_kind}")


async def _process_merkle_proof(db_functions_async: AsynchronousFunctions,
        state: LateHeaderWorkerState, tsc_proof: TSCMerkleProof) -> None:
    assert app_state.headers is not None
    assert tsc_proof.block_hash is not None
    # Do we have the header? If so process it, otherwise record it til the header comes.
    header: Header
    chain: Chain
    try:
        header, chain = app_state.headers.lookup(tsc_proof.block_hash)
    except MissingHeader:
        # We will fetch the proof from the database for matching to later header arrivals.
        # As we have confirmed that at this point the header is not present, monitor it.
        assert tsc_proof.transaction_hash is not None
        state.block_transactions[tsc_proof.block_hash].add(tsc_proof.transaction_hash)
    else:
        # Process all deferred transaction processing for the header's block.
        await _process_block_transactions(db_functions_async, state, header, chain)


async def _process_header(db_functions_async: AsynchronousFunctions,
        state: LateHeaderWorkerState, header: Header, chain: Chain) -> None:
    block_hash = header.hash
    if block_hash in state.block_transactions:
        await _process_block_transactions(db_functions_async, state, header, chain)


async def _process_block_transactions(db_functions_async: AsynchronousFunctions,
        state: LateHeaderWorkerState, header: Header, chain: Chain) -> None:
    assert app_state.headers is not None
    longest_chain = cast(Chain, app_state.headers.longest_chain())
    if chain is longest_chain:
        confirmations = longest_chain.height - header.height
    else:
        # TODO(1.4.0) Make a final decision what to do in this edge case where the chain of the
        #     header is not the longest chain. This would mean the source of the proof is or was
        #     on the reorged chain (or has reorged away from our longest chain). We might want
        #     to do none of this and do something else.
        confirmations = 0

    tx_hashes = list(state.block_transactions[header.hash])
    for tx_hash, flags, tx_block_hash, proof_data in \
            await db_functions_async.read_transaction_proof_data_async(tx_hashes):
        # It is possible that the transaction may have changed from under us in the database,
        # we need to check that it hasn't, but if it has skip the transaction.
        if proof_data is None:
            logger.error("Deferred verification transaction %s block hash now lacks proof data",
                hash_to_hex_str(tx_hash))
            continue

        if flags & TxFlags.MASK_STATE != TxFlags.STATE_CLEARED:
            logger.error("Deferred verification transaction %s state unexpectedly changed "
                "from %r to %r", hash_to_hex_str(tx_hash), TxFlags.STATE_CLEARED,
                TxFlags(flags))
            continue

        if tx_block_hash != header.hash:
            logger.error("Deferred verification transaction %s block hash unexpectedly changed "
                "from %s to %s", hash_to_hex_str(tx_hash), hash_to_hex_str(header.hash),
                hash_to_hex_str(tx_block_hash))
            continue

        tsc_proof = TSCMerkleProof.from_bytes(proof_data)
        if verify_proof(tsc_proof, header.merkle_root):
            if await db_functions_async.update_transaction_flags_async(tx_hash,
                    TxFlags.STATE_SETTLED, ~TxFlags.MASK_STATE):
                callback = state.verification_callback()
                if callback is None:
                    logger.error("Deferred verification transaction %s callback dead",
                        hash_to_hex_str(tx_hash))
                    break
                callback('transaction_verified', tx_hash, header, tsc_proof)
            else:
                logger.error("Deferred verification failed updating transaction %s state "
                    "from %r to %r", hash_to_hex_str(tx_hash), TxFlags(flags),
                    TxFlags.STATE_SETTLED)
        else:
            # TODO(bad-server)
            # TODO(1.4.0) We probably want to know what server this came from so we can treat
            #    it as a bad server. And we would want to retry with a good server.
            logger.error("Deferred verification transaction %s failed verifying proof",
                hash_to_hex_str(tx_hash))
            # Remove the "pending verification" proof and block data from the transaction, it
            # should not be necessary to update the UI as the transaction should not have
            # changed state and we do not display "pending verification" proofs.
            await db_functions_async.update_transaction_proof_async(tx_hash, None, None, None,
                TxFlags.STATE_CLEARED)

    del state.block_transactions[header.hash]

