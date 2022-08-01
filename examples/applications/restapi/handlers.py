# TODO(REST-API-Refactoring) Notes follow.
# - All these functions should be moved out of the example and into the code base proper. We should
#   make a very simple example that extends it as a daemon app.
# - Remove the variables like VERSION, NETWORK, .... a good idea in theory but they overcomplicate
#   things in practice.
# - In `handler_tools.argparser` it should check the type of each variable as it extracts them
#   either from the route or the body and convert them at point of extraction or raise a fault
#   on the first found failed conversion.
# - The only time a wallet name should be passed in the route is at load time for the filename.
#   Beyond that we should use it's ephemeral id, and we should perhaps consider replacing that
#   with a GUID. We should also consider dropping the `.sqlite` suffix from wallet name.
# - Add a `pay` API where the caller just provides a destination address and the wallet manages
#   everything and just returns some result to indicate success.

import asyncio
import atexit
from functools import partial
import json
import os
from pathlib import Path
import shutil
import tempfile
from typing import Any, cast, List, Optional

from aiohttp import web
import bitcoinx
import requests

from electrumsv.app_state import app_state
from electrumsv.bitcoin import COINBASE_MATURITY, script_template_to_string
from electrumsv.constants import AccountCreationType, CredentialPolicyFlag, KeystoreTextType, \
    RECEIVING_SUBPATH
from electrumsv.keystore import instantiate_keystore_from_text
from electrumsv.storage import WalletStorage
from electrumsv.transaction import Transaction
from electrumsv.logs import logs
from electrumsv.networks import BitcoinRegtest, Net
from electrumsv.startup import base_dir
from electrumsv.types import KeyStoreResult, TransactionSize

from .errors import Errors
from .handler_utils import ExtendedHandlerUtils, VNAME, WalletInstanceKind, WalletInstancePaths
from .txstatewebsocket import TxStateWebSocket


logger = logs.get_logger("app_state")

# Makes this code docker-friendly (can access a node on host with "host.docker.internal"
BITCOIN_NODE_HOST = os.environ.get("BITCOIN_NODE_HOST") or "127.0.0.1"
BITCOIN_NODE_PORT = os.environ.get("BITCOIN_NODE_PORT") or 18332
BITCOIN_NODE_RPCUSER = os.environ.get("BITCOIN_NODE_RPCUSER") or "rpcuser"
BITCOIN_NODE_RPCPASSWORD = os.environ.get("BITCOIN_NODE_RPCPASSWORD") or "rpcpassword"
BITCOIN_NODE_URI = f"http://{BITCOIN_NODE_RPCUSER}:{BITCOIN_NODE_RPCPASSWORD}" \
                   f"@{BITCOIN_NODE_HOST}:{BITCOIN_NODE_PORT}"


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

# hardcoded
# - WIF private_key:    cT3G2vJGRNbpmoCVXYPYv2JbngzwtznLvioPPJXu39jfQeLpDuX5
# - Pubkey hash:        mfs8Y8gAwC2vJHCeSXkHs6LF5nu5PA7nxc
REGTEST_FUNDS_PRIVATE_KEY = bitcoinx.PrivateKey(
    bytes.fromhex('a2d9803c912ab380c1491d3bd1aaab34ca06742d7885a224ec8d386182d26ed2'),
    network=BitcoinRegtest)
REGTEST_FUNDS_PRIVATE_KEY_WIF = REGTEST_FUNDS_PRIVATE_KEY.to_WIF()
REGTEST_FUNDS_PUBLIC_KEY: bitcoinx.PublicKey = REGTEST_FUNDS_PRIVATE_KEY.public_key
REGTEST_P2PKH_ADDRESS: str = REGTEST_FUNDS_PUBLIC_KEY.to_address(network=Net.COIN).to_string()


def regtest_get_mined_balance() -> int:
    # Calculate matured balance
    payload = json.dumps({"jsonrpc": "2.0", "method": "listunspent",
                          "params": [1, 1_000_000_000, [REGTEST_P2PKH_ADDRESS]], "id": 1})
    result = requests.post(BITCOIN_NODE_URI, data=payload)
    result.raise_for_status()
    utxos = result.json()['result']
    matured_balance = sum(
        utxo['amount'] for utxo in utxos if utxo['confirmations'] > COINBASE_MATURITY)
    logger.debug("matured coins in regtest slush fund=%s", matured_balance)
    return matured_balance


def import_key(private_key: bitcoinx.PrivateKey) -> None:
    """The node will now monitor this address and therefore track its utxos"""
    payload = json.dumps({"jsonrpc": "2.0", "method": "importprivkey",
                          "params": [private_key.to_WIF()], "id": 1})
    result = requests.post(BITCOIN_NODE_URI, data=payload)
    if result.status_code != 200:
        raise requests.exceptions.HTTPError(result.text)
    p2pkh_address = private_key.public_key.to_address(network=Net.COIN).to_string()
    logger.info("imported address %s into the node wallet for tracking", p2pkh_address)


def regtest_topup_account(receive_address: bitcoinx.P2PKH_Address, amount: int=25) \
        -> Optional[str]:
    import_key(REGTEST_FUNDS_PRIVATE_KEY)
    matured_balance = regtest_get_mined_balance()
    while matured_balance < amount:
        nblocks = 1
        if matured_balance == 0:
            nblocks = 200
        result = node_rpc_call("generatetoaddress", nblocks, REGTEST_P2PKH_ADDRESS)
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

class ExtensionEndpoints(ExtendedHandlerUtils):
    """Extension endpoints for ElectrumSV REST API"""

    routes = list[web.RouteDef]()

    # PATHS
    VERSION = "/v1"
    NETWORK = "/{network}"
    BASE = VERSION + NETWORK + "/dapp"  # avoid conflicts with built-ins
    WALLETS_TLD = BASE + "/wallets"
    WALLETS_PARENT = WALLETS_TLD + "/{wallet_name}"
    WALLETS_ACCOUNT = WALLETS_PARENT + "/{account_id}"
    ACCOUNT_TXS = WALLETS_ACCOUNT + "/txs"
    ACCOUNT_UTXOS = WALLETS_ACCOUNT + "/utxos"

    def __init__(self):
        super().__init__()
        self.logger = logs.get_logger("restapi-dapp")
        self.app_state = app_state  # easier to monkeypatch for testing
        self.add_routes()
        self.temp_dir = tempfile.TemporaryDirectory()

    def cleanup(self) -> None:
        atexit.register(self.temp_dir.cleanup)

    def add_routes(self):
        self.routes = [
            web.get(self.WALLETS_TLD, self.get_all_wallets),
            web.post("/v1/{network}/dapp/wallets/load_instanced", self.load_instanced_wallet),
            web.get(self.WALLETS_PARENT, self.get_parent_wallet),
            web.post(self.WALLETS_PARENT + "/load_wallet", self.load_wallet),
            web.get(self.WALLETS_ACCOUNT, self.get_account),
            web.post("/v1/{network}/dapp/wallets/{wallet_id}/{account_id}/payment_request",
                self.create_payment_request),
            web.get(self.ACCOUNT_UTXOS + "/coin_state", self.get_coin_state),
            web.get(self.ACCOUNT_UTXOS, self.get_utxos),
            web.get(self.ACCOUNT_UTXOS + "/balance", self.get_balance),
            web.delete(self.ACCOUNT_TXS, self.remove_txs),
            web.get(self.ACCOUNT_TXS + "/history", self.get_transaction_history),
            web.post(self.ACCOUNT_TXS + "/fetch", self.fetch_transaction),
            web.post(self.ACCOUNT_TXS + "/create", self.create_tx),
            web.post(self.ACCOUNT_TXS + "/create_and_broadcast", self.create_and_broadcast),
            web.post(self.ACCOUNT_TXS + "/broadcast", self.broadcast),
            web.post(self.ACCOUNT_TXS + "/split_utxos", self.split_utxos),
            web.view(self.ACCOUNT_TXS + "/websocket/text-events", TxStateWebSocket),
        ]

        if app_state.config.get('regtest'):
            self.routes.extend([
                web.post(self.WALLETS_ACCOUNT + "/topup_account", self.topup_account),
                web.post(self.WALLETS_ACCOUNT + "/generate_blocks", self.generate_blocks),
                web.post(self.WALLETS_PARENT + "/create_new_wallet", self.create_new_wallet),
            ])

    # ----- Extends electrumsv/restapi_endpoints ----- #

    async def get_all_wallets(self, request: web.Request) -> web.Response:
        all_parent_wallets = self._get_all_wallets(self.wallets_path)
        response = all_parent_wallets
        return web.json_response({"wallets": response})

    async def get_parent_wallet(self, request: web.Request) -> web.Response:
        """Overview of parent wallet and accounts"""
        vars = await self.argparser(request, required_vars=[VNAME.WALLET_NAME])
        wallet_name = vars[VNAME.WALLET_NAME]

        wallet = self._get_parent_wallet(wallet_name)
        accounts = self._accounts_dto(wallet)
        response = {"parent_wallet": wallet_name,
                    "accounts": accounts}
        return web.json_response(response)

    async def load_instanced_wallet(self, request: web.Request) -> web.Response:
        """
        This copies a pre-generated wallet file to a temporary location and loads it. It can only
        be called once for each wallet instance kind and will error if the instance file name is
        in use. We do not want duplicated wallets reusing keys, it is problems waiting to happen.
        The reason we do this via ids, is that we do not want to allow users to load wallets from
        arbitrary paths.
        """
        vars = await self.argparser(request, required_vars=[VNAME.PASSWORD,
            VNAME.WALLET_INSTANCE_ID])
        valid_instance_ids = set(item.value for item in WalletInstanceKind)
        wallet_instance_id = cast(int, vars[VNAME.WALLET_INSTANCE_ID])
        if wallet_instance_id not in valid_instance_ids:
            raise web.HTTPBadRequest(reason="Unknown wallet instance id")

        relative_wallet_path = WalletInstancePaths[wallet_instance_id]
        wallet_path = os.path.join(base_dir, relative_wallet_path)
        if not os.path.exists(wallet_path):
            raise web.HTTPBadRequest(reason="Invalid wallet path")

        wallet_filename = os.path.basename(wallet_path)
        instanced_wallet_path = os.path.join(self.temp_dir.name, wallet_filename)
        if os.path.exists(instanced_wallet_path):
            raise web.HTTPBadRequest(reason="Wallet in use")
        shutil.copyfile(wallet_path, instanced_wallet_path)

        wallet = await self._load_wallet(instanced_wallet_path, vars[VNAME.PASSWORD],
            enforce_wallet_directory=False)
        accounts = self._accounts_dto(wallet)
        return web.json_response({
            "wallet_id": wallet.get_id(),
            "accounts": accounts
        })

    async def load_wallet(self, request: web.Request) -> web.Response:
        vars = await self.argparser(request, required_vars=[VNAME.PASSWORD, VNAME.WALLET_NAME])
        wallet_name = vars[VNAME.WALLET_NAME]
        wallet = await self._load_wallet(wallet_name, vars[VNAME.PASSWORD])
        accounts = self._accounts_dto(wallet)
        return web.json_response({
            "wallet_id": wallet.get_id(),
            "parent_wallet": wallet_name,
            "accounts": accounts
        })

    async def create_new_wallet(self, request: web.Request) -> web.Response:
        """only for regtest for the moment..."""
        vars = await self.argparser(request, required_vars=[VNAME.PASSWORD, VNAME.WALLET_NAME],
            check_wallet_availability=False)

        create_filepath = str(Path(self.wallets_path).joinpath(vars[VNAME.WALLET_NAME]))
        self.check_if_wallet_exists(create_filepath)

        password_token = app_state.credentials.set_wallet_password(create_filepath,
            vars[VNAME.PASSWORD], CredentialPolicyFlag.FLUSH_AFTER_WALLET_LOAD)
        assert password_token is not None

        storage = WalletStorage.create(create_filepath, password_token)
        storage.close()

        parent_wallet = self.app_state.daemon.load_wallet(create_filepath)
        assert parent_wallet is not None

        # create an account for the Wallet with the same password via an imported seed
        text_type = KeystoreTextType.EXTENDED_PRIVATE_KEY
        text_match = 'tprv8ZgxMBicQKsPd4wsdaJ11eH84eq4hHLX1K6Mx8EQQhJzq8jr25WH1m8hgGkCqnks' \
                        'JDCZPZbDoMbQ6QtroyCyn5ZckCmsLeiHDb1MAxhNUHN'

        keystore = instantiate_keystore_from_text(text_type, text_match, vars[VNAME.PASSWORD],
            derivation_text=None, passphrase='')
        parent_wallet.create_account_from_keystore(
            KeyStoreResult(AccountCreationType.IMPORTED, keystore))
        await self._load_wallet(vars[VNAME.WALLET_NAME], vars[VNAME.PASSWORD])
        response = {"new_wallet": create_filepath}
        return web.json_response(response)

    async def get_account(self, request: web.Request) -> web.Response:
        """Overview of a single 'account"""
        vars = await self.argparser(request, required_vars=[VNAME.WALLET_NAME,
                                                            VNAME.ACCOUNT_ID])
        wallet_name = vars[VNAME.WALLET_NAME]
        account_id = vars[VNAME.ACCOUNT_ID]

        account = self._get_account(wallet_name, account_id)
        response = self._account_dto(account)
        return web.json_response(response)

    async def topup_account(self, request):
        """only for regtest"""
        vars = await self.argparser(request,
            required_vars=[VNAME.WALLET_NAME, VNAME.ACCOUNT_ID])
        wallet_name = vars[VNAME.WALLET_NAME]
        account_id = vars[VNAME.ACCOUNT_ID]
        amount = vars.get(VNAME.AMOUNT, 25)

        account = self._get_account(wallet_name, account_id)

        receive_key = account.get_fresh_keys(RECEIVING_SUBPATH, 1)[0]
        receive_address = account.get_script_template_for_derivation(
            account.get_default_script_type(),
            receive_key.derivation_type, receive_key.derivation_data2)
        txid = regtest_topup_account(receive_address, amount)
        response = {"txid": txid}
        return web.json_response(response)

    async def generate_blocks(self, request):
        """only for regtest"""
        vars = await self.argparser(request,
            required_vars=[VNAME.WALLET_NAME, VNAME.ACCOUNT_ID])
        nblocks = vars.get(VNAME.NBLOCKS, 1)
        txid = regtest_generate_nblocks(nblocks, REGTEST_P2PKH_ADDRESS)
        response = {"txid": txid}
        return web.json_response(response)

    async def create_payment_request(self, request: web.Request) -> web.Response:
        vars = await self.argparser(request, required_vars=[VNAME.WALLET_ID,
            VNAME.ACCOUNT_ID, VNAME.MESSAGE ])
        wallet_id = vars[VNAME.WALLET_ID]
        account_id = vars[VNAME.ACCOUNT_ID]
        message = vars[VNAME.MESSAGE]
        if not len(message):
            raise web.HTTPBadRequest()

        wallet = self._get_wallet_by_id(wallet_id)
        account = self._get_account_from_wallet(wallet, account_id)

        future, key_data = account.create_payment_request(message)
        rows = await asyncio.wrap_future(future)
        if len(rows) != 1:
            raise web.HTTPBadRequest()

        script_type = account.get_default_script_type()
        script_template = account.get_script_template_for_derivation(
            script_type, key_data.derivation_type, key_data.derivation_data2)
        if script_template is None:
            raise web.HTTPBadRequest()

        text = script_template_to_string(script_template)

        return web.json_response({
            "script_type": script_type.name,
            "destination": text,
        })

    async def get_coin_state(self, request: web.Request) -> web.Response:
        """get coin state (unconfirmed and confirmed coin count)"""
        vars = await self.argparser(request, required_vars=[VNAME.WALLET_NAME,
            VNAME.ACCOUNT_ID])
        wallet_name = vars[VNAME.WALLET_NAME]
        account_id = vars[VNAME.ACCOUNT_ID]

        account = self._get_account(wallet_name, account_id)
        response = self._coin_state_dto(account)
        return web.json_response(response)

    async def get_utxos(self, request: web.Request) -> web.Response:
        vars = await self.argparser(request, required_vars=[VNAME.WALLET_NAME,
                                                            VNAME.ACCOUNT_ID])
        wallet_name = vars[VNAME.WALLET_NAME]
        account_id = vars[VNAME.ACCOUNT_ID]
        exclude_frozen = vars.get(VNAME.EXCLUDE_FROZEN, False)
        confirmed_only = vars.get(VNAME.CONFIRMED_ONLY, False)
        mature = vars.get(VNAME.MATURE, True)

        account = self._get_account(wallet_name, account_id)
        utxos = account.get_transaction_outputs_with_key_data(exclude_frozen=exclude_frozen,
                                    confirmed_only=confirmed_only, mature=mature)
        result = self._utxo_dto(utxos)
        response = {"utxos": result}
        return web.json_response(response)

    async def get_balance(self, request: web.Request) -> web.Response:
        """get confirmed, unconfirmed and coinbase balances"""
        vars = await self.argparser(request, required_vars=[VNAME.WALLET_NAME,
                                                            VNAME.ACCOUNT_ID])
        wallet_name = vars[VNAME.WALLET_NAME]
        account_id = vars[VNAME.ACCOUNT_ID]

        account = self._get_account(wallet_name, account_id)
        response = self._balance_dto(wallet=account)
        return web.json_response(response)

    async def remove_txs(self, request: web.Request) -> web.Response:
        # follows this spec https://opensource.zalando.com/restful-api-guidelines/#152
        """This might be used to clean up after creating many transactions that were never sent."""
        vars = await self.argparser(request, required_vars=[VNAME.WALLET_NAME,
                                                            VNAME.ACCOUNT_ID, VNAME.TXIDS])
        wallet_name = vars[VNAME.WALLET_NAME]
        account_id = vars[VNAME.ACCOUNT_ID]
        txids = vars[VNAME.TXIDS]
        account = self._get_account(wallet_name, account_id)

        results = []
        if txids:
            for txid in txids:
                try:
                    self.remove_transaction(bitcoinx.hex_str_to_hash(txid), account)
                    results.append({"id": txid, "result": 200})
                except Fault as e:
                    if e.code == Errors.DISABLED_FEATURE_CODE:
                        results.append({"id": txid, "result": 400,
                                        "description": Errors.DISABLED_FEATURE_MESSAGE})
                    if e.code == Errors.TRANSACTION_NOT_FOUND_CODE:
                        results.append({"id": txid, "result": 400,
                                        "description": Errors.TRANSACTION_NOT_FOUND_MESSAGE})
        return self.batch_response({"items": results})

    async def get_transaction_history(self, request: web.Request) -> web.Response:
        """get transactions - currently only used for debugging via 'postman'"""
        vars = await self.argparser(request, required_vars=[VNAME.WALLET_NAME,
                                                            VNAME.ACCOUNT_ID])
        wallet_name = vars[VNAME.WALLET_NAME]
        account_id = vars[VNAME.ACCOUNT_ID]
        tx_flags = vars.get(VNAME.TX_FLAGS)

        account = self._get_account(wallet_name, account_id)
        response = self._history_dto(account, tx_flags)
        return web.json_response({"history": response})

    async def fetch_transaction(self, request: web.Request) -> web.Response:
        """get transaction"""
        required_vars = [VNAME.WALLET_NAME, VNAME.ACCOUNT_ID, VNAME.TXID]
        vars = await self.argparser(request, required_vars)
        wallet_name = vars[VNAME.WALLET_NAME]
        account_id = vars[VNAME.ACCOUNT_ID]
        txid = vars[VNAME.TXID]

        account = self._get_account(wallet_name, account_id)
        response = self._fetch_transaction_dto(account, tx_id=txid)
        return web.json_response(response)

    async def create_tx(self, request: web.Request) -> web.Response:
        """
        General purpose transaction builder.
        - Should handle any kind of output script.( see bitcoinx.address for
        utilities for building p2pkh, multisig etc outputs as hex strings.)
        """
        tx, account, password = await self._create_tx_helper(request)
        response = {"txid": tx.txid(),
                    "rawtx": str(tx)}
        return web.json_response(response)
        # except Fault as e:
        #     if tx and tx.is_complete() and e.code != Fault(Errors.ALREADY_SENT_TRANSACTION_CODE):
        #         self.cleanup_tx(tx, account)
        #     return fault_to_http_response(e)
        # except Exception as e:
        #     if tx and tx.is_complete():
        #         self.cleanup_tx(tx, account)
        #     return fault_to_http_response(
        #         Fault(code=Errors.GENERIC_INTERNAL_SERVER_ERROR, message=str(e)))

    async def create_and_broadcast(self, request):
        tx, account, password = await self._create_tx_helper(request)
        try:
            result = await self._broadcast_transaction(str(tx), tx.hash(), account)
        except aiorpcx.jsonrpc.RPCError as e:
            raise Fault(Errors.AIORPCX_ERROR_CODE, e.message)
        self.prev_transaction = result
        response = {"txid": result}
        self.logger.debug("successful broadcast for %s", result)
        return web.json_response(response)
        # except Fault as e:
        #     if tx and tx.is_complete() and e.code != Errors.ALREADY_SENT_TRANSACTION_CODE:
        #         self.cleanup_tx(tx, account)
        #     return fault_to_http_response(e)
        # except Exception as e:
        #     self.logger.exception("unexpected error in create_and_broadcast handler")
        #     if tx and tx.is_complete() and not (
        #             isinstance(e, AssertionError) and str(e) == 'duplicate set not supported'):
        #         self.cleanup_tx(tx, account)
        #     return fault_to_http_response(
        #         Fault(code=Errors.GENERIC_INTERNAL_SERVER_ERROR, message=str(e)))

    async def broadcast(self, request: web.Request) -> web.Response:
        """Broadcast a rawtx (hex string) to the network. """
        required_vars = [VNAME.WALLET_NAME, VNAME.ACCOUNT_ID, VNAME.RAWTX]
        vars = await self.argparser(request, required_vars=required_vars)
        wallet_name = vars[VNAME.WALLET_NAME]
        index = vars[VNAME.ACCOUNT_ID]
        rawtx = vars[VNAME.RAWTX]

        account = self._get_account(wallet_name, index)
        tx = Transaction.from_hex(rawtx)
        self.raise_for_duplicate_tx(tx)
        try:
            result = await self._broadcast_transaction(rawtx, tx.hash(), account)
        except aiorpcx.jsonrpc.RPCError as e:
            raise Fault(Errors.AIORPCX_ERROR_CODE, e.message)
        self.prev_transaction = result
        response = {"txid": result}
        return web.json_response(response)

    async def split_utxos(self, request: web.Request) -> web.Response:
        required_vars = [VNAME.WALLET_NAME, VNAME.ACCOUNT_ID, VNAME.SPLIT_COUNT, VNAME.PASSWORD]
        vars = await self.argparser(request, required_vars=required_vars)
        wallet_name = vars[VNAME.WALLET_NAME]
        account_id = vars[VNAME.ACCOUNT_ID]
        split_count = vars[VNAME.SPLIT_COUNT]

        # optional
        split_value = vars.get(VNAME.SPLIT_VALUE, 10000)
        password = vars.get(VNAME.PASSWORD, None)
        desired_utxo_count = vars.get(VNAME.DESIRED_UTXO_COUNT, 2000)
        require_confirmed = vars.get(VNAME.REQUIRE_CONFIRMED, False)

        account = self._get_account(wallet_name, account_id)

        # Approximate size of a transaction with one P2PKH input and one P2PKH output.
        base_fee = self.app_state.config.estimate_fee(TransactionSize(203, 0))
        loop = asyncio.get_event_loop()
        # run in thread - CPU intensive code
        partial_coin_selection = partial(self.select_inputs_and_outputs,
            self.app_state.config, account, base_fee,
            split_count=split_count, desired_utxo_count=desired_utxo_count,
            require_confirmed=require_confirmed, split_value=split_value)

        split_result = await loop.run_in_executor(self.txb_executor, partial_coin_selection)
        # if isinstance(split_result, Fault):
        #     return fault_to_http_response(split_result)
        self.logger.debug("split result: %s", split_result)
        utxos, outputs, attempted_split = split_result
        # if not attempted_split:
        #     fault = Fault(Errors.SPLIT_FAILED_CODE, Errors.SPLIT_FAILED_MESSAGE)
        #     return fault_to_http_response(fault)
        tx, tx_context = account.make_unsigned_transaction(utxos, outputs)
        future = account.sign_transaction(tx, password, tx_context)
        if future is not None:
            future.result()
        self.raise_for_duplicate_tx(tx)

        # broadcast
        result = await self._broadcast_transaction(str(tx), tx.hash(), account)
        self.prev_transaction = result
        response = {"txid": result}
        return web.json_response(response)
        # except Fault as e:
        #     if tx and tx.is_complete() and e.code != Fault(Errors.ALREADY_SENT_TRANSACTION_CODE):
        #         self.cleanup_tx(tx, account)
        #     return fault_to_http_response(e)
        # except InsufficientCoinsError as e:
        #     self.logger.debug(Errors.INSUFFICIENT_COINS_MESSAGE)
        #     return fault_to_http_response(
        #         Fault(Errors.INSUFFICIENT_COINS_CODE, Errors.INSUFFICIENT_COINS_MESSAGE))
        # except Exception as e:
        #     if tx and tx.is_complete():
        #         self.cleanup_tx(tx, account)
        #     return fault_to_http_response(
        #         Fault(code=Errors.GENERIC_INTERNAL_SERVER_ERROR, message=str(e)))
