import json
import logging
import os
import time
from typing import Any, cast, List, Optional, Tuple, TYPE_CHECKING

import requests
from bitcoinx import Chain, Header, Headers, MissingHeader, CheckPoint, bits_to_work, \
    P2PKH_Address, hash_to_hex_str
from urllib3.exceptions import NewConnectionError

from .bitcoin import COINBASE_MATURITY
from .networks import Net, BLOCK_HEIGHT_OUT_OF_RANGE_ERROR
from .logs import logs

if TYPE_CHECKING:
    from .app_state import AppStateProxy


MAX_BITS = 0x1d00ffff

logger = logs.get_logger("app_state")

# Makes this code docker-friendly (can access a node on host with "host.docker.internal"
BITCOIN_NODE_HOST = os.environ.get("BITCOIN_NODE_HOST") or "127.0.0.1"
BITCOIN_NODE_PORT = os.environ.get("BITCOIN_NODE_PORT") or 18332
BITCOIN_NODE_RPCUSER = os.environ.get("BITCOIN_NODE_RPCUSER") or "rpcuser"
BITCOIN_NODE_RPCPASSWORD = os.environ.get("BITCOIN_NODE_RPCPASSWORD") or "rpcpassword"
BITCOIN_NODE_URI = f"http://{BITCOIN_NODE_RPCUSER}:{BITCOIN_NODE_RPCPASSWORD}" \
                   f"@{BITCOIN_NODE_HOST}:{BITCOIN_NODE_PORT}"


# NOTE(typing) The `Headers` class is untyped so we need to silence mypy telling us that.
class HeadersRegTestMod(Headers): # type: ignore

    def connect(self, raw_header: bytes) -> Tuple[Header, Chain]:
        """overwrite Headers method to skip checking of difficulty target"""
        header = self.coin.deserialized_header(raw_header, -1)
        prev_header, chain = self.lookup(header.prev_hash)
        header.height = prev_header.height + 1
        # If the chain tip is the prior header then this header is new.  Otherwise we must check.
        if chain.tip.hash != prev_header.hash:
            try:
                return cast(Tuple[Header, Chain], self.lookup(header.hash))
            except MissingHeader:
                pass
        header_index = self._storage.append(raw_header)
        chain = self._read_header(header_index)
        return header, chain


def delete_headers_file(path_to_headers: str) -> None:
    if os.path.exists(path_to_headers):
        os.remove(path_to_headers)


def setup_regtest(app_state: "AppStateProxy") -> HeadersRegTestMod:
    while True:
        try:
            regtest_import_privkey_to_node()
            delete_headers_file(app_state.headers_filename())
            Net._net.CHECKPOINT, Net._net.VERIFICATION_BLOCK_MERKLE_ROOT = \
                calculate_regtest_checkpoint(Net.MIN_CHECKPOINT_HEIGHT)
            logger.info("using regtest network - miner funds go to: '%s' (not part of this wallet)",
                        Net.REGTEST_P2PKH_ADDRESS)
            break
        except (NewConnectionError, requests.exceptions.ConnectionError) as e:
            sleep_time = 5.0
            logger.error(f"node is offline, retrying in {sleep_time} seconds...")
            time.sleep(sleep_time)
        except Exception:
            break

    return cast(HeadersRegTestMod,
        HeadersRegTestMod.from_file(Net.COIN, app_state.headers_filename(), Net.CHECKPOINT))


def node_rpc_call(method_name: str, *args: Any) -> Any:
    result = None
    try:
        if not args:
            params = []
        else:
            params = [*args]
        payload = json.dumps({"jsonrpc": "2.0", "method": f"{method_name}", "params": params,
            "id": 0})
        result = requests.post(BITCOIN_NODE_URI, data=payload)
        result.raise_for_status()
        return result
    except requests.exceptions.HTTPError as e:
        if result is not None:
            logger.error(result.json()['error']['message'])
        raise e


def regtest_topup_account(receive_address: P2PKH_Address, amount: int=25) -> Optional[str]:
    matured_balance = regtest_get_mined_balance()
    while matured_balance < amount:
        nblocks = 1
        if matured_balance == 0:
            nblocks = 200
        result = node_rpc_call("generatetoaddress", nblocks, Net.REGTEST_P2PKH_ADDRESS)
        if result.status_code == 200:
            logger.debug(f"generated {nblocks}: {result.json()['result']}")
        matured_balance = regtest_get_mined_balance()

    # Note: for bare multi-sig support may need to craft rawtxs manually via bitcoind's
    #  'signrawtransaction' jsonrpc method - AustEcon
    payload = json.dumps({"jsonrpc": "2.0", "method": "sendtoaddress",
                          "params": [receive_address.to_string(), amount], "id": 0})
    result = requests.post(BITCOIN_NODE_URI, data=payload)
    if result.status_code != 200:
        raise requests.exceptions.HTTPError(result.text)
    txid = cast(str, result.json()['result'])
    logger.info("topped up wallet with %s coins to receive address='%s'. txid=%s", amount,
        receive_address.to_string(), txid)
    return txid


def regtest_import_privkey_to_node() -> None:
    logger.info("importing hardcoded regtest private key '%s' to bitcoind wallet",
        Net.REGTEST_FUNDS_PRIVATE_KEY_WIF)
    payload = json.dumps(
        {"jsonrpc": "2.0", "method": "importprivkey",
         "params": [Net.REGTEST_FUNDS_PRIVATE_KEY_WIF], "id": 0})
    result = requests.post(BITCOIN_NODE_URI, data=payload)
    result.raise_for_status()


def regtest_get_mined_balance() -> int:
    # Calculate matured balance
    payload = json.dumps({"jsonrpc": "2.0", "method": "listunspent",
                          "params": [1, 1_000_000_000, [Net.REGTEST_P2PKH_ADDRESS]], "id": 0})
    result = requests.post(BITCOIN_NODE_URI, data=payload)
    result.raise_for_status()
    utxos = result.json()['result']
    matured_balance = sum(
        utxo['amount'] for utxo in utxos if utxo['confirmations'] > COINBASE_MATURITY)
    logger.debug("matured coins in regtest slush fund=%s", matured_balance)
    return matured_balance


def regtest_generate_nblocks(nblocks: int, address: str) -> List[str]:
    payload1 = json.dumps(
        {"jsonrpc": "2.0", "method": "generatetoaddress", "params": [nblocks, address],
         "id": 0})
    result = requests.post(BITCOIN_NODE_URI, data=payload1)
    result.raise_for_status()
    block_hashes = []
    for block_hash in cast(List[str], result.json()['result']):
        block_hashes.append(block_hash)
        logger.debug("newly mined blockhash: %s", block_hash)
    logger.debug("mined %s new blocks (funds to address=%s). use the "
                 "'regtest_topup_account' method to fund your account", nblocks, address)
    return block_hashes


def get_blockhash_by_height(height: int) -> str:
    payload = json.dumps(
        {"jsonrpc": "2.0", "method": "getblockbyheight", "params": [height], "id": height})
    result = requests.post(BITCOIN_NODE_URI, data=payload)
    result.raise_for_status()
    hash_hex = result.json()['result']['hash']
    return cast(str, hash_hex)


def get_raw_block_header_by_hash(hash_hex: str) -> bytes:
    payload = json.dumps(
        {"jsonrpc": "2.0", "method": "getblockheader", "params": [hash_hex, False], "id": 1})
    result = requests.post(BITCOIN_NODE_URI, data=payload)
    checkpoint_raw_header = bytes.fromhex(result.json()['result'])
    return checkpoint_raw_header


def calculate_regtest_checkpoint(height: int) -> Tuple[CheckPoint, Optional[str]]:
    logging.getLogger("urllib3").setLevel(logging.WARNING)  # suppress excessive logging
    try:
        hash_ = get_blockhash_by_height(height)
        checkpoint_raw_header = get_raw_block_header_by_hash(hash_)

        # RegTest nBits overflow the max allowable value so cap the nBits at max
        prev_work = sum((bits_to_work(MAX_BITS) for i in range(Net.MIN_CHECKPOINT_HEIGHT - 1)))

        checkpoint = CheckPoint(raw_header=checkpoint_raw_header,
            height=Net.MIN_CHECKPOINT_HEIGHT, prev_work=prev_work)
        verification_block_merkle_root = None if Net.MIN_CHECKPOINT_HEIGHT < 150 \
            else hash_to_hex_str(checkpoint_raw_header[36:68])
        return checkpoint, verification_block_merkle_root

    except requests.HTTPError as e:
        if e.response.json().get('error').get('code') == BLOCK_HEIGHT_OUT_OF_RANGE_ERROR:
            regtest_generate_nblocks(200, address=Net.REGTEST_P2PKH_ADDRESS)
            # retry with more blocks
            return calculate_regtest_checkpoint(height)
        raise e
