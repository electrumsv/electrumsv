import asyncio
import os
from functools import partial
from typing import Optional, Union, List, Dict, Any, Iterable, Tuple

import aiorpcx
import bitcoinx
from bitcoinx import TxOutput
from aiohttp import web
from electrumsv.coinchooser import PRNG
from electrumsv.constants import TxFlags, MAX_MESSAGE_BYTES
from electrumsv.transaction import Transaction
from electrumsv.wallet import Abstract_Wallet, ParentWallet, UTXO
from .logs import logs
from .app_state import app_state
from .restapi import Fault, Errors, decode_request_body, good_response, fault_to_http_response, \
    get_network_type


class HandlerUtils:

    # Request variables
    class VARNAMES:
        WALLET_NAME = 'wallet_name'
        INDEX = 'index'
        PASSWORD = 'password'
        RAWTX = 'rawtx'
        TXIDS = 'txids'
        UTXOS = 'utxos'
        OUTPUTS = 'outputs'
        UTXO_PRESELECTION = 'utxo_preselection'
        REQUIRE_CONFIRMED = 'require_confirmed'
        EXCLUDE_FROZEN = 'exclude_frozen'
        CONFIRMED_ONLY = 'confirmed_only'
        MATURE = 'mature'

    # Request types
    ARGTYPES = {
        VARNAMES.WALLET_NAME: str,
        VARNAMES.INDEX: str,
        VARNAMES.PASSWORD: str,
        VARNAMES.RAWTX: str,
        VARNAMES.TXIDS: list,
        VARNAMES.UTXOS: list,
        VARNAMES.OUTPUTS: list,
        VARNAMES.REQUIRE_CONFIRMED: bool,
        VARNAMES.EXCLUDE_FROZEN: bool,
        VARNAMES.CONFIRMED_ONLY: bool,
        VARNAMES.MATURE: bool,
        VARNAMES.UTXO_PRESELECTION: bool
    }

    # Response variables...
    # Response types...

    def __init__(self):
        self.logger = logs.get_logger("handler-utils")
        self.wallets_path = os.path.join(app_state.config.electrum_path(), "wallets")
        self.all_wallets = self._get_all_wallets(self.wallets_path)
        self.app_state = app_state  # easier to monkeypatch for testing
        self.prev_transaction = ''

    # ---- Parse Header and Body variables ----- #

    def _get_var_from_header(self, request: web.Request, var_name: str,
            required: bool = True, default=None) -> Union[str, int, Fault]:
        var = request.match_info.get(var_name, default)
        if var is None and required:
            return Fault(code=Errors.HEADER_VAR_NOT_PROVIDED_CODE,
                         message=Errors.HEADER_VAR_NOT_PROVIDED_MESSAGE.format(var_name))

        if var_name == self.VARNAMES.WALLET_NAME:
            return self.wallet_if_available(var)

        if var_name == self.VARNAMES.INDEX:
            return self.index_if_isdigit(var)

        return var

    async def _get_var_from_body(self, body: Dict, var_name: str, required: bool = True,
                                 default=None) -> Union[Any, Fault]:

        if isinstance(body, Fault):
            if not required:
                return default
            elif required and body.code == Errors.EMPTY_REQUEST_BODY_CODE:
                return Fault(code=Errors.BODY_VAR_NOT_PROVIDED_CODE,
                             message=Errors.BODY_VAR_NOT_PROVIDED_MESSAGE.format(var_name))
            return body  # JSONDecodeError

        var = body.get(var_name, default)
        if not var and required:
            return Fault(code=Errors.BODY_VAR_NOT_PROVIDED_CODE,
                         message=Errors.BODY_VAR_NOT_PROVIDED_MESSAGE.format(var_name))
        if not var and not required:
            return default

        # check types
        if not isinstance(var, self.ARGTYPES.get(var_name)):
            message = f"{var_name} must be of type: '{self.ARGTYPES[var_name]}'"
            return Fault(code=Errors.GENERIC_BAD_REQUEST_CODE, message=message)

        # other checks
        if var_name == self.VARNAMES.WALLET_NAME:
            return self.wallet_if_available(var)

        if var_name == self.VARNAMES.OUTPUTS:
            return self.outputs_from_dicts(var)

        if var_name == self.VARNAMES.UTXOS:
            return self.utxos_from_dicts(var)

        return var

    # ----- Support functions ----- #

    def index_if_isdigit(self, index: str) -> Union[int, Fault]:
        if not index.isdigit():
            message = "child wallet index in url must be an integer. You tried " \
                      "index='%s'." % index
            return Fault(code=Errors.GENERIC_BAD_REQUEST_CODE, message=message)
        return int(index)

    def wallet_if_available(self, wallet_name) -> Union[str, Fault]:
        if not self._wallet_name_available(wallet_name):
            return Fault(code=Errors.WALLET_NOT_FOUND_CODE,
                         message=Errors.WALLET_NOT_FOUND_MESSAGE.format(wallet_name))
        return wallet_name

    def outputs_from_dicts(self, outputs: List[Dict[str, Any]]) -> List[TxOutput]:
        outputs_from_dicts = []
        for output in outputs:
            spk = bitcoinx.Script.from_hex(output.get('script_pubkey'))
            outputs_from_dicts.append(bitcoinx.TxOutput(value=output.get('value'),
                                                        script_pubkey=spk))
        return outputs_from_dicts

    def utxos_from_dicts(self, utxos: List[Dict[str, Any]]) -> List[UTXO]:
        utxos_from_dicts = []
        for utxo in utxos:
            utxos_from_dicts.append(UTXO.from_dict(utxo))
        return utxos_from_dicts

    async def send_request(self, method, args):
        session = await self.app_state.daemon.network._main_session()
        return await session.send_request(method, args)

    def check_for_duplicate_tx(self, tx):
        """because the network can be very slow to give this important feedback and instead will
        return the txid as an http 200 response."""
        if tx.txid() == self.prev_transaction:
            message = "You've already sent this transaction: {}".format(tx.txid())
            fault = Fault(Errors.ALREADY_SENT_TRANSACTION_CODE, message)
            return fault
        return

    def preselect_utxos(self, utxos, outputs, batch_size=10):
        """Inexact, random pre-selectiion of utxos for performance reasons.
        'make_unsigned_transaction' is slow if it iterates over all utxos.
        - Disabled via {'utxo_preselection': False} in body of request."""
        BATCH_SIZE = batch_size
        if len(utxos) <= BATCH_SIZE:
            return utxos  # abort

        selected_utxos = []
        # Deterministic randomness from coins (only select first 10 (or batch_size) for speed)
        p = PRNG(b''.join(sorted(
            bitcoinx.hex_str_to_hash(utxo.tx_hash) for utxo in utxos[0:BATCH_SIZE])))

        tx = Transaction.from_io([], outputs)
        # Size of the transaction with no inputs and no change
        base_size = tx.estimated_size()
        spent_amount = tx.output_value()
        fee_estimator = lambda size: app_state.config.estimate_fee(size)

        def sufficient_funds(selected_utxos):
            """Given a list of utxos, return True if it has enough
            value to pay for the transaction"""
            INPUT_SIZE = 148
            CHANGE_SAFE_MARGIN = 34 * 1000  # enough for 1000 change outputs
            total_input = sum(utxo.value for utxo in selected_utxos)
            total_size = sum(INPUT_SIZE for utxo in selected_utxos) + base_size + CHANGE_SAFE_MARGIN
            return total_input >= spent_amount + fee_estimator(total_size)

        # add batches of 10 utxos before sufficient_funds() check
        batch = []
        for i in range(1, len(utxos)):
            utxo = p.pluck(utxos)
            batch.append(utxo)
            if i % BATCH_SIZE == 0:
                selected_utxos.extend(batch)
                batch = []
                if sufficient_funds(selected_utxos):
                    return selected_utxos
                else:
                    continue
        return utxos  # may still be enough coins

    def _get_wallet_path(self, wallet_name: str) -> Union[Fault, str]:
        """returns parent wallet path. The wallet_name must include .sqlite extension"""
        wallet_path = os.path.join(self.wallets_path, wallet_name)
        wallet_path = os.path.normpath(wallet_path)
        if wallet_name != os.path.basename(wallet_path):
            return Fault(Errors.BAD_WALLET_NAME_CODE,
                         Errors.BAD_WALLET_NAME_MESSAGE)
        if os.path.exists(wallet_path):
            return wallet_path
        else:
            return Fault(Errors.WALLET_NOT_FOUND_CODE,
                         Errors.WALLET_NOT_FOUND_MESSAGE)

    def _get_all_wallets(self, wallets_path) -> List[str]:
        """returns all parent wallet paths"""
        all_parent_wallets = os.listdir(wallets_path)
        return sorted(all_parent_wallets)

    def _get_parent_wallet(self, wallet_name: str) -> Union[Fault, ParentWallet]:
        """returns a child wallet object"""
        path_result = self._get_wallet_path(wallet_name)
        if isinstance(path_result, Fault):
            return path_result
        parent_wallet = self.app_state.daemon.get_wallet(path_result)
        if not parent_wallet:
            message = Errors.LOAD_BEFORE_GET_MESSAGE.format(get_network_type(),
                                                            'wallet_name.sqlite')
            return Fault(code=Errors.LOAD_BEFORE_GET_CODE, message=message)
        return parent_wallet

    def _get_child_wallet(self, wallet_name: str, index: int=0) \
            -> Union[Fault, Abstract_Wallet]:
        parent_wallet = self._get_parent_wallet(wallet_name=wallet_name)
        if isinstance(parent_wallet, Fault):
            return parent_wallet
        try:
            child_wallet = parent_wallet.get_wallet_for_account(index)
        except IndexError:
            message = f"There is no child wallet at index: {index}."
            return Fault(Errors.WALLET_NOT_FOUND_CODE, message)
        return child_wallet

    def _is_wallet_ready(self, wallet_name: Optional[str]=None) -> Union[Fault, bool]:
        wallet = self._get_parent_wallet(wallet_name)
        if isinstance(wallet, Fault):
            return wallet
        return wallet.is_synchronized()

    async def _delete_signed_txs(self, wallet_name: str, index: int) -> Optional[Fault]:
        """Unfreezes all StateSigned transactions and deletes them from cache and database"""
        while True:
            is_ready = self._is_wallet_ready(wallet_name)
            if isinstance(is_ready, Fault):
                return is_ready

            if is_ready:
                # Unfreeze all StateSigned transactions but leave StateDispatched frozen
                wallet = self._get_child_wallet(wallet_name, index)
                if isinstance(wallet, Fault):
                    return wallet

                utxos = wallet.get_utxos(exclude_frozen=False)
                signed_transactions = self._get_transactions(wallet_name=wallet_name,
                    flags=TxFlags.StateSigned, index=index)

                for txid, tx in signed_transactions:
                    utxo_keys = set([(bitcoinx.hash_to_hex_str(input.prev_hash), input.prev_idx)
                                     for input in tx.inputs])
                    frozen_utxos = [utxo for utxo in utxos if utxo.key() in utxo_keys]
                    wallet.set_frozen_coin_state(frozen_utxos, False)
                    wallet.delete_transaction(txid)
                break
            await asyncio.sleep(0.1)
        return

    async def _load_wallet(self, wallet_name: Optional[str] = None,
                           password: Optional[str] = None) -> Union[Fault, ParentWallet]:
        """Loads one parent wallet into the daemon and begins synchronization"""
        if not wallet_name.endswith(".sqlite"):
            wallet_name += ".sqlite"

        path_result = self._get_wallet_path(wallet_name)
        if isinstance(path_result, Fault):
            return path_result

        parent_wallet = self.app_state.daemon.load_wallet(path_result, password)
        if parent_wallet is None:
            return Fault(Errors.WALLET_NOT_LOADED_CODE,
                         Errors.WALLET_NOT_LOADED_MESSAGE)
        return parent_wallet

    def _get_transactions(self, wallet_name: Optional[str]=None, flags: Optional[int]=None,
                          index: int=0):
        """returns a list of transactions with a given TxState flag."""
        wallet = self._get_child_wallet(wallet_name, index)
        if isinstance(wallet, Fault):
            return wallet
        txs = wallet._datastore.tx.get_transactions(flags=flags)
        return txs

    def _wallet_name_available(self, wallet_name) -> bool:
        if wallet_name in self.all_wallets:
            return True
        return False

    def _check_message_size(self, message_bytes) -> Union[bool, Fault]:
        if len(message_bytes) > MAX_MESSAGE_BYTES:
            return Fault(Errors.DATA_TOO_BIG_CODE,
                         Errors.DATA_TOO_BIG_MESSAGE)

    def _get_and_set_frozen_utxos_for_tx(self, tx: Transaction, child_wallet: Abstract_Wallet) \
            -> List[UTXO]:
        spendable_coins = child_wallet.get_spendable_coins(None, {})
        input_keys = set([
            (bitcoinx.hash_to_hex_str(input.prev_hash), input.prev_idx) for input in tx.inputs])
        frozen_utxos = [utxo for utxo in spendable_coins if utxo.key() in input_keys]
        child_wallet.set_frozen_coin_state(frozen_utxos, True)
        return frozen_utxos

    # ----- Data transfer objects ----- #

    def _balance_dto(self, wallet) -> Dict[Any, Any]:
        confirmed_bal, unconfirmed_bal, mature_coinbase_bal = wallet.get_balance()
        return {"confirmed_balance": confirmed_bal + mature_coinbase_bal,
                "unconfirmed_balance": unconfirmed_bal}

    def _utxo_dto(self, utxos: List[UTXO]) -> List[Dict]:
        utxos_as_dicts = []
        for utxo in utxos:
            utxos_as_dicts.append(utxo.as_dict())
        return utxos_as_dicts

    def _coin_state_dto(self, wallet) -> Union[Fault, Dict[str, Any]]:
        all_coins = wallet.get_spendable_coins(None, {})
        cleared_coins = len([coin for coin in all_coins if coin.height < 1])
        settled_coins = len([coin for coin in all_coins if coin.height >= 1])
        return {"cleared_coins": cleared_coins,
                "settled_coins": settled_coins}

    def _history_dto(self, wallet: Abstract_Wallet) -> List[Dict[Any, Any]]:
        history = wallet.export_history()
        return history

    def _transaction_state_dto(self, wallet: Abstract_Wallet,
        tx_ids: Optional[Iterable[str]]=None) -> Union[Fault, Dict[Any, Any]]:

        chain = self.app_state.daemon.network.chain()

        result = {}
        for tx_id in tx_ids:
            if wallet.has_received_transaction(tx_id):
                # height, conf, timestamp
                height, conf, timestamp = wallet.get_tx_height(tx_id)
                block_id = None
                if timestamp:
                    block_id = self.app_state.headers.header_at_height(chain, height).hex_str()
                result[tx_id] = {
                    "block_id": block_id,
                    "height": height,
                    "conf": conf,
                    "timestamp": timestamp,
                }
        return result

    def _child_wallet_dto(self, wallet) -> Dict[Any, Any]:
        """child wallet data transfer object"""
        return {wallet._id: {"wallet_type": wallet.dump()['wallet_type'],
                             "is_wallet_ready": wallet.is_synchronized()}}

    def _child_wallets_dto(self, parent_wallet: ParentWallet):
        """child wallets data transfer object"""
        child_wallets = {}
        for wallet in parent_wallet.get_child_wallets():
            child_wallets.update(self._child_wallet_dto(wallet))
        return child_wallets


class DefaultEndpoints(HandlerUtils):

    routes = web.RouteTableDef()

    def __init__(self):
        super().__init__()
        self.logger = logs.get_logger("restapi-default-endpoints")
        self.app_state = app_state  # easier to monkeypatch for testing

    # ----- External API ----- #

    @routes.get("/")
    async def status(self, request):
        return good_response({"status": "success"})

    @routes.get("/v1/{network}/ping")
    async def ping(self, request):
        return good_response({"value": "pong"})

    @routes.get("/v1/{network}/wallets")
    async def get_all_wallets(self, request):
        all_parent_wallets = self._get_all_wallets(self.wallets_path)
        response = {"value": all_parent_wallets}
        return good_response(response)

    @routes.get("/v1/{network}/wallets/{wallet_name}")
    async def get_parent_wallet(self, request):
        """Overview of parent wallet and 'accounts' (a.k.a. child_wallets)"""
        # Note: Return value is currently quite sparse - room to add much more.
        # parse headers
        wallet_name = self._get_var_from_header(request, self.VARNAMES.WALLET_NAME, required=True)

        if isinstance(wallet_name, Fault):
            return fault_to_http_response(wallet_name)

        parent_wallet = self._get_parent_wallet(wallet_name)
        if isinstance(parent_wallet, Fault):
            return fault_to_http_response(parent_wallet)

        child_wallets = self._child_wallets_dto(parent_wallet)
        response = {"parent_wallet": wallet_name,
                    "value": child_wallets}
        return good_response(response)

    @routes.get("/v1/{network}/wallets/{wallet_name}/{index}")
    async def get_child_wallet(self, request):
        """Overview of a single 'account' (a.k.a. child_wallets)"""
        # Note: Return value is currently quite sparse - room to add much more.
        # parse headers
        index = self._get_var_from_header(request, self.VARNAMES.INDEX, required=True)
        wallet_name = self._get_var_from_header(request, self.VARNAMES.WALLET_NAME, required=True)

        for var in (index, wallet_name):
            if isinstance(var, Fault):
                return fault_to_http_response(var)

        child_wallet = self._get_child_wallet(wallet_name, index)
        if isinstance(child_wallet, Fault):
            return fault_to_http_response(child_wallet)

        ret_val = self._child_wallet_dto(child_wallet)
        response = {"value": ret_val}
        return good_response(response)

    @routes.post("/v1/{network}/wallets/{wallet_name}/load_wallet")
    async def load_wallet(self, request):
        # parse headers
        wallet_name = self._get_var_from_header(request, self.VARNAMES.WALLET_NAME, required=True)

        # parse body
        body = await decode_request_body(request)
        password = await self._get_var_from_body(body, self.VARNAMES.PASSWORD, required=False)

        for var in (wallet_name, password):
            if isinstance(var, Fault):
                return fault_to_http_response(var)

        parent_wallet = await self._load_wallet(wallet_name, password=password)
        if isinstance(parent_wallet, Fault):
            return fault_to_http_response(parent_wallet)

        child_wallets = self._child_wallets_dto(parent_wallet)
        response = {"parent_wallet": wallet_name,
                    "value": child_wallets}
        return good_response(response)

    @routes.post("/v1/{network}/wallets/{wallet_name}/{index}/txs/delete_signed_txs")
    async def delete_signed_txs(self, request):
        """This might be used to clean up after creating many transactions that were never sent."""
        # parse headers
        index = self._get_var_from_header(request, self.VARNAMES.INDEX, required=True)
        wallet_name = self._get_var_from_header(request, self.VARNAMES.WALLET_NAME, required=True)

        for var in (index, wallet_name):
            if isinstance(var, Fault):
                return fault_to_http_response(var)

        result = await self._delete_signed_txs(wallet_name, index)
        if isinstance(result, Fault):
            return fault_to_http_response(result)

        ret_val = {"value": {"message": "All StateSigned transactions deleted from TxCache, "
                                        "TxInputs and TxOutputs cache and SqliteDatabase. "
                                        "Corresponding utxos also removed from frozen list."}}
        return good_response(ret_val)

    @routes.get("/v1/{network}/wallets/{wallet_name}/{index}/balance")
    async def get_balance(self, request):
        """get confirmed, unconfirmed and coinbase balances"""
        # parse headers
        index = self._get_var_from_header(request, "index", required=True)
        wallet_name = self._get_var_from_header(request, 'wallet_name', required=True)

        for var in (index, wallet_name):
            if isinstance(var, Fault):
                return fault_to_http_response(var)

        child_wallet = self._get_child_wallet(wallet_name, index)
        if isinstance(child_wallet, Fault):
            return fault_to_http_response(child_wallet)

        ret_val = self._balance_dto(wallet=child_wallet)
        response = {"value": ret_val}
        return good_response(response)

    @routes.get("/v1/{network}/wallets/{wallet_name}/{index}/txs/history")
    async def get_transaction_history(self, request):
        """get transactions - currently only used for debugging via 'postman'"""
        # parse headers
        index = self._get_var_from_header(request, "index", required=True)
        wallet_name = self._get_var_from_header(request, 'wallet_name', required=True)

        for var in (index, wallet_name):
            if isinstance(var, Fault):
                return fault_to_http_response(var)

        child_wallet = self._get_child_wallet(wallet_name, index)
        if isinstance(child_wallet, Fault):
            return fault_to_http_response(child_wallet)

        ret_val = self._history_dto(wallet=child_wallet)
        response = {"value": ret_val}
        return good_response(response)

    @routes.post("/v1/{network}/wallets/{wallet_name}/{index}/txs/metadata")
    async def get_transactions_metadata(self, request):
        """get transaction metadata"""
        # parse headers
        index = self._get_var_from_header(request, self.VARNAMES.INDEX, required=True)
        wallet_name = self._get_var_from_header(request, self.VARNAMES.WALLET_NAME, required=True)

        # parse body
        body = await decode_request_body(request)
        tx_ids = await self._get_var_from_body(body, self.VARNAMES.TXIDS, required=True)

        for var in (index, wallet_name, tx_ids):
            if isinstance(var, Fault):
                return fault_to_http_response(var)

        child_wallet = self._get_child_wallet(wallet_name, index)
        if isinstance(child_wallet, Fault):
            return fault_to_http_response(child_wallet)

        # noinspection PyTypeChecker
        ret_val = self._transaction_state_dto(child_wallet, tx_ids=tx_ids)
        response = {"value": ret_val}
        return good_response(response)

    @routes.get("/v1/{network}/wallets/{wallet_name}/{index}/utxos/coin_state")
    async def get_coin_state(self, request):
        """get coin state (unconfirmed and confirmed coin count)"""
        # parse headers
        index = self._get_var_from_header(request, self.VARNAMES.INDEX, required=True)
        wallet_name = self._get_var_from_header(request, self.VARNAMES.WALLET_NAME, required=True)

        for var in (index, wallet_name):
            if isinstance(var, Fault):
                return fault_to_http_response(var)

        child_wallet = self._get_child_wallet(wallet_name, index)
        if isinstance(child_wallet, Fault):
            return fault_to_http_response(child_wallet)

        result = self._coin_state_dto(wallet=child_wallet)
        response = {"value": result}
        return good_response(response)

    @routes.get("/v1/{network}/wallets/{wallet_name}/{index}/utxos")
    async def get_utxos(self, request) -> Union[Fault, Any]:
        # Note: child_wallet.get_utxos is currently quite slow - needs canonical utxo cache
        # parse headers
        index = self._get_var_from_header(request, self.VARNAMES.INDEX, required=True)
        wallet_name = self._get_var_from_header(request, self.VARNAMES.WALLET_NAME, required=True)
        # parse body
        body = await decode_request_body(request)
        if isinstance(body, Fault) and not body.code == 40005:
            return fault_to_http_response(body)
        gvfb = partial(self._get_var_from_body, body)
        exclude_frozen = await gvfb(self.VARNAMES.EXCLUDE_FROZEN, required=False, default=False)
        confirmed_only = await gvfb(self.VARNAMES.CONFIRMED_ONLY, required=False, default=False)
        mature = await gvfb('mature', required=False, default=True)

        for var in (index, wallet_name):
            if isinstance(var, Fault):
                return fault_to_http_response(var)

        child_wallet = self._get_child_wallet(wallet_name, index)
        if isinstance(child_wallet, Fault):
            return fault_to_http_response(child_wallet)

        utxos = child_wallet.get_utxos(domain=None, exclude_frozen=exclude_frozen,
                                       confirmed_only=confirmed_only, mature=mature)
        result = self._utxo_dto(utxos)
        response = {"value": {"utxos": result}}
        return good_response(response)

    async def _create_tx_argparser(self, request) -> Union[Tuple, Fault]:
        # parse headers
        index = self._get_var_from_header(request, self.VARNAMES.INDEX, required=True)
        wallet_name = self._get_var_from_header(request, self.VARNAMES.WALLET_NAME, required=True)

        # parse body
        body = await decode_request_body(request)
        if isinstance(body, Fault):
            return body
        gvfb = partial(self._get_var_from_body, body)
        outputs = await gvfb(self.VARNAMES.OUTPUTS, required=True)
        utxos = await gvfb(self.VARNAMES.UTXOS, required=False, default=None)
        utxo_preselection = await gvfb(self.VARNAMES.UTXO_PRESELECTION, required=False, default=True)
        password = await gvfb(self.VARNAMES.PASSWORD, required=False)
        confirmed_only = await gvfb(self.VARNAMES.CONFIRMED_ONLY, required=False, default=False)

        for var in (index, wallet_name, outputs, utxos, password, confirmed_only,
                    utxo_preselection):
            if isinstance(var, Fault):
                return var

        return index, wallet_name, outputs, utxos, password, confirmed_only, \
            utxo_preselection

    async def _create_tx_helper(self, request) -> Union[Tuple, Fault]:
        vars = await self._create_tx_argparser(request)
        if isinstance(vars, Fault):
            return vars

        index, wallet_name, outputs, utxos, password, confirmed_only, utxo_preselection = vars

        child_wallet = self._get_child_wallet(wallet_name, index)
        if isinstance(child_wallet, Fault):
            return child_wallet

        if not utxos:
            utxos = child_wallet.get_spendable_coins(None, self.app_state.config)

        if utxo_preselection:  # Defaults to True
            utxos = self.preselect_utxos(utxos, outputs)

        # Todo - loop.run_in_executor
        tx = child_wallet.make_unsigned_transaction(utxos, outputs, self.app_state.config)
        return tx, child_wallet, password

    @routes.post("/v1/{network}/wallets/{wallet_name}/{index}/txs/create")
    async def create_tx(self, request):
        """
        General purpose transaction builder.
        - Should handle any kind of output script.( see bitcoinx.address for
        utilities for building p2pkh, multisig etc outputs as hex strings.)
        """
        vars = await self._create_tx_helper(request)
        if isinstance(vars, Fault):
            return fault_to_http_response(vars)
        tx, child_wallet, password = vars

        child_wallet.sign_transaction(tx, password)
        _frozen_utxos = self._get_and_set_frozen_utxos_for_tx(tx, child_wallet)

        response = {"value": {"txid": tx.txid(),
                              "rawtx": str(tx)}}
        return good_response(response)

    @routes.post("/v1/{network}/wallets/{wallet_name}/{index}/txs/create_and_broadcast")
    async def create_and_broadcast(self, request):
        vars = await self._create_tx_helper(request)
        if isinstance(vars, Fault):
            return fault_to_http_response(vars)
        tx, child_wallet, password = vars

        check = self.check_for_duplicate_tx(tx)
        if isinstance(check, Fault):
            return fault_to_http_response(check)

        child_wallet.sign_transaction(tx, password)
        frozen_utxos = self._get_and_set_frozen_utxos_for_tx(tx, child_wallet)

        try:
            result = await self.send_request('blockchain.transaction.broadcast', [str(tx)])
        except aiorpcx.jsonrpc.RPCError as e:
            child_wallet.set_frozen_coin_state(frozen_utxos, False)
            return fault_to_http_response(Fault(Errors.AIORPCX_ERROR_CODE, e.message))
        self.prev_transaction = result
        response = {"value": {"txid": result}}
        return good_response(response)

    @routes.post("/v1/{network}/wallets/{wallet_name}/{index}/txs/broadcast")
    async def broadcast(self, request):
        """Broadcast a rawtx (hex string) to the network. """
        # parse headers
        index = self._get_var_from_header(request, "index", required=True)
        wallet_name = self._get_var_from_header(request, 'wallet_name', required=True)

        # parse body
        body = await decode_request_body(request)
        if isinstance(body, Fault):
            return fault_to_http_response(body)

        gvfb = partial(self._get_var_from_body, body)
        rawtx = await gvfb(self.VARNAMES.RAWTX, required=True)
        password = await gvfb(self.VARNAMES.PASSWORD, required=False)

        for var in (index, wallet_name, password):
            if isinstance(var, Fault):
                return fault_to_http_response(var)

        child_wallet = self._get_child_wallet(wallet_name, index)
        if isinstance(child_wallet, Fault):
            return fault_to_http_response(child_wallet)

        tx = Transaction.from_hex(rawtx)
        check = self.check_for_duplicate_tx(tx)
        if isinstance(check, Fault):
            return fault_to_http_response(check)
        frozen_utxos = self._get_and_set_frozen_utxos_for_tx(tx, child_wallet)

        try:
            result = await self.send_request('blockchain.transaction.broadcast', [rawtx])
        except aiorpcx.jsonrpc.RPCError as e:
            child_wallet.set_frozen_coin_state(frozen_utxos, False)
            return fault_to_http_response(Fault(Errors.AIORPCX_ERROR_CODE, e.message))
        self.prev_transaction = result
        response = {"value": {"txid": result}}
        return good_response(response)
