from typing import Union, Any
import aiorpcx
from aiohttp import web
from electrumsv.restapi_endpoints import DefaultEndpoints
from electrumsv.transaction import Transaction
from electrumsv.logs import logs
from electrumsv.app_state import app_state
from electrumsv.restapi import Fault, good_response, \
    fault_to_http_response
from .errors import Errors

from .handler_utils import ExtendedHandlerUtils, VNAME


class ExtensionEndpoints(ExtendedHandlerUtils, DefaultEndpoints):
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
            web.get("/", self.status),
            web.get(self.BASE + "/ping", self.ping),
            web.get(self.WALLETS_TLD, self.get_all_wallets),
            web.get(self.WALLETS_PARENT, self.get_parent_wallet),
            web.post(self.WALLETS_PARENT + "/load_wallet", self.load_wallet),
            web.get(self.WALLETS_ACCOUNT, self.get_account),
            web.get(self.ACCOUNT_UTXOS + "/coin_state", self.get_coin_state),
            web.get(self.ACCOUNT_UTXOS, self.get_utxos),
            web.get(self.ACCOUNT_UTXOS + "/balance", self.get_balance),
            web.post(self.ACCOUNT_TXS + "/delete_signed_txs", self.delete_signed_txs),
            web.get(self.ACCOUNT_TXS + "/history", self.get_transaction_history),
            web.post(self.ACCOUNT_TXS + "/metadata", self.get_transactions_metadata),
            web.post(self.ACCOUNT_TXS + "/fetch", self.fetch_transaction),
            web.post(self.ACCOUNT_TXS + "/create", self.create_tx),
            web.post(self.ACCOUNT_TXS + "/create_and_broadcast", self.create_and_broadcast),
            web.post(self.ACCOUNT_TXS + "/broadcast", self.broadcast)
        ]

    # ----- Extends electrumsv/restapi_endpoints ----- #

    async def get_all_wallets(self, request):
        try:
            all_parent_wallets = self._get_all_wallets(self.wallets_path)
            response = {"value": all_parent_wallets}
            return good_response(response)
        except Fault as e:
            return fault_to_http_response(e)

    async def get_parent_wallet(self, request):
        """Overview of parent wallet and accounts"""
        try:
            vars = await self.argparser(request, required_vars=[VNAME.WALLET_NAME])
            wallet_name = vars[VNAME.WALLET_NAME]

            wallet = self._get_parent_wallet(wallet_name)
            accounts = self._accounts_dto(wallet)
            response = {"parent_wallet": wallet_name, "value": accounts}
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
                        "value": accounts}
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
            ret_val = self._account_dto(account)
            response = {"value": ret_val}
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
            result = self._coin_state_dto(wallet=account)
            response = {"value": result}
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
            response = {"value": {"utxos": result}}
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
            ret_val = self._balance_dto(wallet=account)
            response = {"value": ret_val}
            return good_response(response)
        except Fault as e:
            return fault_to_http_response(e)

    async def delete_signed_txs(self, request):
        """This might be used to clean up after creating many transactions that were never sent."""
        try:
            vars = await self.argparser(request, required_vars=[VNAME.WALLET_NAME,
                                                                VNAME.ACCOUNT_ID])
            wallet_name = vars[VNAME.WALLET_NAME]
            account_id = vars[VNAME.ACCOUNT_ID]

            await self._delete_signed_txs(wallet_name, account_id)
            ret_val = {"value": {"message": "All StateSigned transactions deleted from TxCache, "
                                            "TxInputs and TxOutputs cache and SqliteDatabase. "
                                            "Corresponding utxos also removed from frozen list."}}
            return good_response(ret_val)
        except Fault as e:
            return fault_to_http_response(e)

    async def get_transaction_history(self, request):
        """get transactions - currently only used for debugging via 'postman'"""
        try:
            vars = await self.argparser(request, required_vars=[VNAME.WALLET_NAME,
                                                                VNAME.ACCOUNT_ID])
            wallet_name = vars[VNAME.WALLET_NAME]
            account_id = vars[VNAME.ACCOUNT_ID]

            account = self._get_account(wallet_name, account_id)
            ret_val = self._history_dto(wallet=account)
            response = {"value": ret_val}
            return good_response(response)
        except Fault as e:
            return fault_to_http_response(e)

    async def get_transactions_metadata(self, request):
        """get transaction metadata"""
        try:
            required_vars = [VNAME.WALLET_NAME, VNAME.ACCOUNT_ID, VNAME.TXIDS]
            vars = await self.argparser(request, required_vars)
            wallet_name = vars[VNAME.WALLET_NAME]
            account_id = vars[VNAME.ACCOUNT_ID]
            txids = vars[VNAME.TXIDS]

            account = self._get_account(wallet_name, account_id)
            ret_val = self._transaction_state_dto(account, tx_ids=txids)
            response = {"value": ret_val}
            return good_response(response)
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
            ret_val = self._fetch_transaction_dto(account, tx_id=txid)
            response = {"value": ret_val}
            return good_response(response)
        except Fault as e:
            return fault_to_http_response(e)

    async def create_tx(self, request):
        """
        General purpose transaction builder.
        - Should handle any kind of output script.( see bitcoinx.address for
        utilities for building p2pkh, multisig etc outputs as hex strings.)
        """
        try:
            tx, account, password = await self._create_tx_helper(request)
            self.raise_for_duplicate_tx(tx)
            account.sign_transaction(tx, password)

            # freeze utxos by default (if broadcast not attempted will remain frozen)
            _frozen_utxos = self.app_state.app.get_and_set_frozen_utxos_for_tx(tx, account)
            response = {"value": {"txid": tx.txid(),
                                  "rawtx": str(tx)}}
            return good_response(response)
        except Fault as e:
            return fault_to_http_response(e)

    async def create_and_broadcast(self, request):
        try:
            tx, account, password = await self._create_tx_helper(request)
            self.raise_for_duplicate_tx(tx)
            account.sign_transaction(tx, password)
            frozen_utxos = self.app_state.app.get_and_set_frozen_utxos_for_tx(tx, account)
            result = await self.send_request('blockchain.transaction.broadcast', [str(tx)])
            self.prev_transaction = result
            response = {"value": {"txid": result}}
            self.logger.debug("successful broadcast for %s", result)
            return good_response(response)
        except Fault as e:
            return fault_to_http_response(e)
        except aiorpcx.jsonrpc.RPCError as e:
            account.set_frozen_coin_state(frozen_utxos, False)
            return fault_to_http_response(Fault(Errors.AIORPCX_ERROR_CODE, e.message))

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
            frozen_utxos = self.app_state.app.get_and_set_frozen_utxos_for_tx(tx, account)
            result = await self.send_request('blockchain.transaction.broadcast', [rawtx])
            self.logger.debug("successful broadcast for %s", result)
            self.prev_transaction = result
            response = {"value": {"txid": result}}
            return good_response(response)
        except Fault as e:
            return fault_to_http_response(e)
        except aiorpcx.jsonrpc.RPCError as e:
            account.set_frozen_coin_state(frozen_utxos, False)
            return fault_to_http_response(Fault(Errors.AIORPCX_ERROR_CODE, e.message))
