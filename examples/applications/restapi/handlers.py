import asyncio
from functools import partial
from pathlib import Path
from typing import Union, Any

import aiorpcx
import bitcoinx
from aiohttp import web
from electrumsv.constants import RECEIVING_SUBPATH, KeystoreTextType
from electrumsv.keystore import instantiate_keystore_from_text
from electrumsv.storage import WalletStorage
from electrumsv.networks import Net
from electrumsv.transaction import Transaction
from electrumsv.logs import logs
from electrumsv.app_state import app_state
from electrumsv.restapi import Fault, good_response, fault_to_http_response
from electrumsv.regtest_support import regtest_generate_nblocks, regtest_topup_account
from .errors import Errors
from .handler_utils import ExtendedHandlerUtils, VNAME, InsufficientCoinsError


class ExtensionEndpoints(ExtendedHandlerUtils):
    """Extension endpoints for ElectrumSV REST API"""

    routes = []

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

    def add_routes(self):
        self.routes = [
            web.get(self.WALLETS_TLD, self.get_all_wallets),
            web.get(self.WALLETS_PARENT, self.get_parent_wallet),
            web.post(self.WALLETS_PARENT + "/load_wallet", self.load_wallet),
            web.get(self.WALLETS_ACCOUNT, self.get_account),
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
        ]

        if app_state.config.get('regtest'):
            self.routes.extend([
                web.post(self.WALLETS_ACCOUNT + "/topup_account", self.topup_account),
                web.post(self.WALLETS_ACCOUNT + "/generate_blocks", self.generate_blocks),
                web.post(self.WALLETS_PARENT + "/create_new_wallet", self.create_new_wallet),
            ])

    # ----- Extends electrumsv/restapi_endpoints ----- #

    async def get_all_wallets(self, request):
        try:
            all_parent_wallets = self._get_all_wallets(self.wallets_path)
            response = all_parent_wallets
            return good_response({"wallets": response})
        except Fault as e:
            return fault_to_http_response(e)

    async def get_parent_wallet(self, request):
        """Overview of parent wallet and accounts"""
        try:
            vars = await self.argparser(request, required_vars=[VNAME.WALLET_NAME])
            wallet_name = vars[VNAME.WALLET_NAME]

            wallet = self._get_parent_wallet(wallet_name)
            accounts = self._accounts_dto(wallet)
            response = {"parent_wallet": wallet_name,
                        "accounts": accounts}
            return good_response(response)
        except Fault as e:
            return fault_to_http_response(e)

    async def load_wallet(self, request):
        try:
            vars = await self.argparser(request, required_vars=[VNAME.WALLET_NAME])
            wallet_name = vars[VNAME.WALLET_NAME]
            parent_wallet = await self._load_wallet(wallet_name)
            accounts = self._accounts_dto(parent_wallet)
            response = {"parent_wallet": wallet_name,
                        "accounts": accounts}
            return good_response(response)
        except Fault as e:
            return fault_to_http_response(e)

    async def create_new_wallet(self, request):
        """only for regtest for the moment..."""
        try:
            vars = await self.argparser(request, required_vars=[VNAME.PASSWORD, VNAME.WALLET_NAME],
                check_wallet_availability=False)

            create_filepath = str(Path(self.wallets_path).joinpath(vars[VNAME.WALLET_NAME]))
            self.check_if_wallet_exists(create_filepath)

            storage = WalletStorage.create(create_filepath, vars[VNAME.PASSWORD])
            storage.close()

            parent_wallet = self.app_state.daemon.load_wallet(create_filepath)

            # create an account for the Wallet with the same password via an imported seed
            text_type = KeystoreTextType.EXTENDED_PRIVATE_KEY
            text_match = 'tprv8ZgxMBicQKsPd4wsdaJ11eH84eq4hHLX1K6Mx8EQQhJzq8jr25WH1m8hgGkCqnks' \
                         'JDCZPZbDoMbQ6QtroyCyn5ZckCmsLeiHDb1MAxhNUHN'

            keystore = instantiate_keystore_from_text(text_type, text_match, vars[VNAME.PASSWORD],
                derivation_text=None, passphrase=None)
            parent_wallet.create_account_from_keystore(keystore)
            await self._load_wallet(vars[VNAME.WALLET_NAME])
            response = {"new_wallet": create_filepath}
            return good_response(response)
        except Fault as e:
            return fault_to_http_response(e)

    async def get_account(self, request):
        """Overview of a single 'account"""
        try:
            vars = await self.argparser(request, required_vars=[VNAME.WALLET_NAME,
                                                                VNAME.ACCOUNT_ID])
            wallet_name = vars[VNAME.WALLET_NAME]
            account_id = vars[VNAME.ACCOUNT_ID]

            account = self._get_account(wallet_name, account_id)
            response = self._account_dto(account)
            return good_response(response)
        except Fault as e:
            return fault_to_http_response(e)

    async def topup_account(self, request):
        """only for regtest"""
        try:
            vars = await self.argparser(request,
                required_vars=[VNAME.WALLET_NAME, VNAME.ACCOUNT_ID])
            wallet_name = vars[VNAME.WALLET_NAME]
            account_id = vars[VNAME.ACCOUNT_ID]
            amount = vars.get(VNAME.AMOUNT, 25)

            account = self._get_account(wallet_name, account_id)

            receive_key = account.get_fresh_keys(RECEIVING_SUBPATH, 1)[0]
            receive_address = account.get_script_template_for_id(receive_key.keyinstance_id)
            txid = regtest_topup_account(receive_address, amount)
            response = {"txid": txid}
            return good_response(response)
        except Fault as e:
            return fault_to_http_response(e)

    async def generate_blocks(self, request):
        """only for regtest"""
        try:
            vars = await self.argparser(request,
                required_vars=[VNAME.WALLET_NAME, VNAME.ACCOUNT_ID])
            nblocks = vars.get(VNAME.NBLOCKS, 1)
            txid = regtest_generate_nblocks(nblocks, Net.REGTEST_P2PKH_ADDRESS)
            response = {"txid": txid}
            return good_response(response)
        except Fault as e:
            return fault_to_http_response(e)

    async def get_coin_state(self, request):
        """get coin state (unconfirmed and confirmed coin count)"""
        try:
            vars = await self.argparser(request, required_vars=[VNAME.WALLET_NAME,
                VNAME.ACCOUNT_ID])
            wallet_name = vars[VNAME.WALLET_NAME]
            account_id = vars[VNAME.ACCOUNT_ID]

            account = self._get_account(wallet_name, account_id)
            response = self._coin_state_dto(account)
            return good_response(response)
        except Fault as e:
            return fault_to_http_response(e)

    async def get_utxos(self, request) -> Union[Fault, Any]:
        try:
            vars = await self.argparser(request, required_vars=[VNAME.WALLET_NAME,
                                                                VNAME.ACCOUNT_ID])
            wallet_name = vars[VNAME.WALLET_NAME]
            account_id = vars[VNAME.ACCOUNT_ID]
            exclude_frozen = vars.get(VNAME.EXCLUDE_FROZEN, False)
            confirmed_only = vars.get(VNAME.CONFIRMED_ONLY, False)
            mature = vars.get(VNAME.MATURE, True)

            account = self._get_account(wallet_name, account_id)
            utxos = account.get_utxos(exclude_frozen=exclude_frozen,
                                      confirmed_only=confirmed_only, mature=mature)
            result = self._utxo_dto(utxos)
            response = {"utxos": result}
            return good_response(response)
        except Fault as e:
            return fault_to_http_response(e)

    async def get_balance(self, request):
        """get confirmed, unconfirmed and coinbase balances"""
        try:
            vars = await self.argparser(request, required_vars=[VNAME.WALLET_NAME,
                                                                VNAME.ACCOUNT_ID])
            wallet_name = vars[VNAME.WALLET_NAME]
            account_id = vars[VNAME.ACCOUNT_ID]

            account = self._get_account(wallet_name, account_id)
            response = self._balance_dto(wallet=account)
            return good_response(response)
        except Fault as e:
            return fault_to_http_response(e)

    async def remove_txs(self, request):
        # follows this spec https://opensource.zalando.com/restful-api-guidelines/#152
        """This might be used to clean up after creating many transactions that were never sent."""
        try:
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
        except Fault as e:
            return fault_to_http_response(e)

    async def get_transaction_history(self, request):
        """get transactions - currently only used for debugging via 'postman'"""
        try:
            vars = await self.argparser(request, required_vars=[VNAME.WALLET_NAME,
                                                                VNAME.ACCOUNT_ID])
            wallet_name = vars[VNAME.WALLET_NAME]
            account_id = vars[VNAME.ACCOUNT_ID]
            tx_flags = vars.get(VNAME.TX_FLAGS)

            account = self._get_account(wallet_name, account_id)
            response = self._history_dto(account, tx_flags)
            return good_response({"history": response})
        except Fault as e:
            return fault_to_http_response(e)

    async def fetch_transaction(self, request):
        """get transaction"""
        try:
            required_vars = [VNAME.WALLET_NAME, VNAME.ACCOUNT_ID, VNAME.TXID]
            vars = await self.argparser(request, required_vars)
            wallet_name = vars[VNAME.WALLET_NAME]
            account_id = vars[VNAME.ACCOUNT_ID]
            txid = vars[VNAME.TXID]

            account = self._get_account(wallet_name, account_id)
            response = self._fetch_transaction_dto(account, tx_id=txid)
            return good_response(response)
        except Fault as e:
            return fault_to_http_response(e)

    async def create_tx(self, request):
        """
        General purpose transaction builder.
        - Should handle any kind of output script.( see bitcoinx.address for
        utilities for building p2pkh, multisig etc outputs as hex strings.)
        """
        account = None
        tx = None
        try:
            tx, account, password = await self._create_tx_helper(request)
            response = {"txid": tx.txid(),
                        "rawtx": str(tx)}
            return good_response(response)
        except Fault as e:
            if tx and tx.is_complete() and e.code != Fault(Errors.ALREADY_SENT_TRANSACTION_CODE):
                self.cleanup_tx(tx, account)
            return fault_to_http_response(e)
        except Exception as e:
            if tx and tx.is_complete():
                self.cleanup_tx(tx, account)
            return fault_to_http_response(
                Fault(code=Errors.GENERIC_INTERNAL_SERVER_ERROR, message=str(e)))

    async def create_and_broadcast(self, request):
        account = None
        tx = None
        try:
            tx, account, password = await self._create_tx_helper(request)
            try:
                result = await self._broadcast_transaction(str(tx), tx.hash(), account)
            except aiorpcx.jsonrpc.RPCError as e:
                raise Fault(Errors.AIORPCX_ERROR_CODE, e.message)
            self.prev_transaction = result
            response = {"txid": result}
            self.logger.debug("successful broadcast for %s", result)
            return good_response(response)
        except Fault as e:
            if tx and tx.is_complete() and e.code != Errors.ALREADY_SENT_TRANSACTION_CODE:
                self.cleanup_tx(tx, account)
            return fault_to_http_response(e)
        except Exception as e:
            self.logger.exception("unexpected error in create_and_broadcast handler")
            if tx and tx.is_complete() and not (
                    isinstance(e, AssertionError) and str(e) == 'duplicate set not supported'):
                self.cleanup_tx(tx, account)
            return fault_to_http_response(
                Fault(code=Errors.GENERIC_INTERNAL_SERVER_ERROR, message=str(e)))

    async def broadcast(self, request):
        """Broadcast a rawtx (hex string) to the network. """
        try:
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
            return good_response(response)
        except Fault as e:
            return fault_to_http_response(e)

    async def split_utxos(self, request) -> Union[Fault, Any]:
        account = None
        tx = None
        try:
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
            base_fee = self.app_state.config.estimate_fee(203)
            loop = asyncio.get_event_loop()
            # run in thread - CPU intensive code
            partial_coin_selection = partial(self.select_inputs_and_outputs,
                self.app_state.config, account, base_fee,
                split_count=split_count, desired_utxo_count=desired_utxo_count,
                require_confirmed=require_confirmed, split_value=split_value)

            split_result = await loop.run_in_executor(self.txb_executor, partial_coin_selection)
            if isinstance(split_result, Fault):
                return fault_to_http_response(split_result)
            self.logger.debug("split result: %s", split_result)
            utxos, outputs, attempted_split = split_result
            if not attempted_split:
                fault = Fault(Errors.SPLIT_FAILED_CODE, Errors.SPLIT_FAILED_MESSAGE)
                return fault_to_http_response(fault)
            tx = account.make_unsigned_transaction(utxos, outputs, self.app_state.config)
            account.sign_transaction(tx, password)
            self.raise_for_duplicate_tx(tx)

            # broadcast
            result = await self._broadcast_transaction(str(tx), tx.hash(), account)
            self.prev_transaction = result
            response = {"txid": result}
            return good_response(response)
        except Fault as e:
            if tx and tx.is_complete() and e.code != Fault(Errors.ALREADY_SENT_TRANSACTION_CODE):
                self.cleanup_tx(tx, account)
            return fault_to_http_response(e)
        except InsufficientCoinsError as e:
            self.logger.debug(Errors.INSUFFICIENT_COINS_MESSAGE)
            self.logger.debug("utxos remaining: %s", account.get_utxos())
            return fault_to_http_response(
                Fault(Errors.INSUFFICIENT_COINS_CODE, Errors.INSUFFICIENT_COINS_MESSAGE))
        except Exception as e:
            if tx and tx.is_complete():
                self.cleanup_tx(tx, account)
            return fault_to_http_response(
                Fault(code=Errors.GENERIC_INTERNAL_SERVER_ERROR, message=str(e)))
