import asyncio
import os
from json import JSONDecodeError
from typing import Optional, Union, List, Dict, Any, Iterable, Tuple
import bitcoinx
from bitcoinx import TxOutput
from aiohttp import web
from electrumsv.coinchooser import PRNG
from electrumsv.constants import TxFlags, MAX_MESSAGE_BYTES
from electrumsv.networks import Net
from electrumsv.restapi_endpoints import HandlerUtils, VARNAMES, ARGTYPES
from electrumsv.transaction import Transaction
from electrumsv.wallet import Abstract_Wallet, ParentWallet, UTXO
from electrumsv.logs import logs
from electrumsv.app_state import app_state
from electrumsv.restapi import Fault, get_network_type, decode_request_body
from .errors import Errors


# Request variables
class VNAME(VARNAMES):
    NETWORK = 'network'
    INDEX = 'index'
    WALLET_NAME = 'wallet_name'
    PASSWORD = 'password'
    RAWTX = 'rawtx'
    TXIDS = 'txids'
    TXID = 'txid'
    UTXOS = 'utxos'
    OUTPUTS = 'outputs'
    UTXO_PRESELECTION = 'utxo_preselection'
    REQUIRE_CONFIRMED = 'require_confirmed'
    EXCLUDE_FROZEN = 'exclude_frozen'
    CONFIRMED_ONLY = 'confirmed_only'
    MATURE = 'mature'


# Request types
ADDITIONAL_ARGTYPES: Dict[str, type] = {
    VNAME.NETWORK: str,
    VNAME.INDEX: str,
    VNAME.WALLET_NAME: str,
    VNAME.PASSWORD: str,
    VNAME.RAWTX: str,
    VNAME.TXIDS: list,
    VNAME.TXID: str,
    VNAME.UTXOS: list,
    VNAME.OUTPUTS: list,
    VNAME.REQUIRE_CONFIRMED: bool,
    VNAME.EXCLUDE_FROZEN: bool,
    VNAME.CONFIRMED_ONLY: bool,
    VNAME.MATURE: bool,
    VNAME.UTXO_PRESELECTION: bool
}

ARGTYPES.update(ADDITIONAL_ARGTYPES)

HEADER_VARS = [VNAME.NETWORK, VNAME.INDEX, VNAME.WALLET_NAME]
BODY_VARS = [VNAME.PASSWORD, VNAME.RAWTX, VNAME.TXIDS, VNAME.UTXOS, VNAME.OUTPUTS,
             VNAME.UTXO_PRESELECTION, VNAME.REQUIRE_CONFIRMED, VNAME.EXCLUDE_FROZEN,
             VNAME.CONFIRMED_ONLY, VNAME.MATURE]


class ExtendedHandlerUtils(HandlerUtils):
    """Extends ElectrumSV HandlerUtils"""

    def __init__(self):
        super().__init__()
        self.logger = logs.get_logger("ext-handler-utils")
        self.wallets_path = os.path.join(app_state.config.electrum_path(), "wallets")
        self.all_wallets = self._get_all_wallets(self.wallets_path)
        self.app_state = app_state  # easier to monkeypatch for testing
        self.prev_transaction = ''

    # ---- Parse Header and Body variables ----- #

    def raise_for_var_missing(self, vars, required_vars: List[str]):
        for varname in required_vars:
            if vars.get(varname) is None:
                if varname in HEADER_VARS:
                    raise Fault(Errors.HEADER_VAR_NOT_PROVIDED_CODE,
                                Errors.HEADER_VAR_NOT_PROVIDED_MESSAGE.format(varname))
                else:
                    raise Fault(Errors.BODY_VAR_NOT_PROVIDED_CODE,
                                Errors.BODY_VAR_NOT_PROVIDED_MESSAGE.format(varname))

    def raise_for_type_okay(self, vars):
        for vname in vars:
            if vars.get(vname, None):
                if not isinstance(vars.get(vname), ARGTYPES.get(vname)):
                    message = f"{vars.get(vname)} must be of type: '{ARGTYPES.get(vname)}'"
                    raise Fault(Errors.GENERIC_BAD_REQUEST_CODE, message)

    def index_if_isdigit(self, index: str) -> Union[int, Fault]:
        if not index.isdigit():
            message = "child wallet index in url must be an integer. You tried " \
                      "index='%s'." % index
            raise Fault(code=Errors.GENERIC_BAD_REQUEST_CODE, message=message)
        return int(index)

    def raise_for_wallet_availability(self, wallet_name: str) -> Union[str, Fault]:
        if not self._wallet_name_available(wallet_name):
            raise Fault(code=Errors.WALLET_NOT_FOUND_CODE,
                         message=Errors.WALLET_NOT_FOUND_MESSAGE.format(wallet_name))
        return wallet_name

    def get_header_vars(self, request) -> Dict:
        header_vars = {}
        for varname in HEADER_VARS:
            header_vars.update({varname: request.match_info.get(varname)})
        return header_vars

    async def get_body_vars(self, request) -> Dict:
        try:
            return await decode_request_body(request)
        except JSONDecodeError as e:
            message = "JSONDecodeError " + str(e)
            raise Fault(Errors.JSON_DECODE_ERROR_CODE, message)

    async def argparser(self, request: web.Request, required_vars: List=None) -> Optional[Dict]:
        """Extracts and checks all standardized header and body variables from the request object
        as a dictionary to feed to the handlers."""
        vars: Dict[Any] = {}
        header_vars = self.get_header_vars(request)
        body_vars = await self.get_body_vars(request)
        vars.update(header_vars)
        vars.update(body_vars)
        self.raise_for_type_okay(vars)

        wallet_name = vars.get(VNAME.WALLET_NAME)
        if wallet_name:
            self.raise_for_wallet_availability(wallet_name)

        index = vars.get(VNAME.INDEX)
        if index:
            vars[VNAME.INDEX] = self.index_if_isdigit(index)

        outputs = vars.get(VNAME.OUTPUTS)
        if outputs:
            vars[VNAME.OUTPUTS] = self.outputs_from_dicts(outputs)

        utxos = vars.get(VNAME.UTXOS)
        if utxos:
            vars[VNAME.UTXOS] = self.utxos_from_dicts(utxos)

        if required_vars:
            self.raise_for_var_missing(vars, required_vars)

        return vars

    # ----- Support functions ----- #

    def utxo_as_dict(self, utxo):
        # 'address' paradigm to be deprecated soon
        return {"address": utxo.address.to_string(),
                "height": utxo.height,
                "is_coinbase": utxo.is_coinbase,
                "out_index": utxo.out_index,
                "script_pubkey": utxo.script_pubkey.to_hex(),
                "tx_hash": utxo.tx_hash,
                "value": utxo.value}

    def utxo_from_dict(self, d):
        return UTXO(
            address=bitcoinx.Address.from_string(d['address'], coin=Net.COIN),
            height=d['height'],
            is_coinbase=d['is_coinbase'],
            out_index=d['out_index'],
            script_pubkey=bitcoinx.Script.from_hex(d['script_pubkey']),
            tx_hash=d['tx_hash'],
            value=d['value'],
        )

    def outputs_from_dicts(self, outputs: Optional[List[Dict[str, Any]]]) -> List[TxOutput]:
        outputs_from_dicts = []
        for output in outputs:
            spk = bitcoinx.Script.from_hex(output.get('script_pubkey'))
            outputs_from_dicts.append(bitcoinx.TxOutput(value=output.get('value'),
                                                        script_pubkey=spk))
        return outputs_from_dicts

    def utxos_from_dicts(self, utxos: Optional[List[Dict[str, Any]]]) -> List[UTXO]:
        utxos_from_dicts = []
        for utxo in utxos:
            utxos_from_dicts.append(self.utxo_from_dict(utxo))
        return utxos_from_dicts

    def raise_for_duplicate_tx(self, tx):
        """because the network can be very slow to give this important feedback and instead will
        return the txid as an http 200 response."""
        if tx.txid() == self.prev_transaction:
            message = "You've already sent this transaction: {}".format(tx.txid())
            fault = Fault(Errors.ALREADY_SENT_TRANSACTION_CODE, message)
            raise fault
        return

    def _get_wallet_path(self, wallet_name: str) -> str:
        """returns parent wallet path. The wallet_name must include .sqlite extension"""
        wallet_path = os.path.join(self.wallets_path, wallet_name)
        wallet_path = os.path.normpath(wallet_path)
        if wallet_name != os.path.basename(wallet_path):
            raise Fault(Errors.BAD_WALLET_NAME_CODE,
                         Errors.BAD_WALLET_NAME_MESSAGE)
        if os.path.exists(wallet_path):
            return wallet_path
        else:
            raise Fault(Errors.WALLET_NOT_FOUND_CODE,
                         Errors.WALLET_NOT_FOUND_MESSAGE)

    def _get_all_wallets(self, wallets_path) -> List[str]:
        """returns all parent wallet paths"""
        all_parent_wallets = os.listdir(wallets_path)
        return sorted(all_parent_wallets)

    def _get_parent_wallet(self, wallet_name: str) -> ParentWallet:
        """returns a child wallet object"""
        path_result = self._get_wallet_path(wallet_name)
        parent_wallet = self.app_state.daemon.get_wallet(path_result)
        if not parent_wallet:
            message = Errors.LOAD_BEFORE_GET_MESSAGE.format(get_network_type(),
                                                            'wallet_name.sqlite')
            raise Fault(code=Errors.LOAD_BEFORE_GET_CODE, message=message)
        return parent_wallet

    def _get_child_wallet(self, wallet_name: str, index: int=0) \
            -> Union[Fault, Abstract_Wallet]:
        parent_wallet = self._get_parent_wallet(wallet_name=wallet_name)
        try:
            child_wallet = parent_wallet.get_wallet_for_account(index)
        except IndexError:
            message = f"There is no child wallet at index: {index}."
            raise Fault(Errors.WALLET_NOT_FOUND_CODE, message)
        return child_wallet

    def _is_wallet_ready(self, wallet_name: Optional[str]=None) -> Union[Fault, bool]:
        wallet = self._get_parent_wallet(wallet_name)
        return wallet.is_synchronized()

    async def _delete_signed_txs(self, wallet_name: str, index: int) -> Optional[Fault]:
        """Unfreezes all StateSigned transactions and deletes them from cache and database"""
        while True:
            is_ready = self._is_wallet_ready(wallet_name)

            if is_ready:
                # Unfreeze all StateSigned transactions but leave StateDispatched frozen
                wallet = self._get_child_wallet(wallet_name, index)
                signed_transactions = wallet._datastore.tx.get_transactions(
                    flags=TxFlags.StateSigned)

                for txid, tx in signed_transactions:
                    app_state.app.get_and_set_frozen_utxos_for_tx(tx, wallet, freeze=False)
                    wallet.delete_transaction(txid)
                break
            await asyncio.sleep(0.1)
        return

    async def send_request(self, method, args):
        session = await self.app_state.daemon.network._main_session()
        return await session.send_request(method, args)

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
        fee_estimator = app_state.config.estimate_fee

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

    async def _load_wallet(self, wallet_name: Optional[str] = None,
                           password: Optional[str] = None) -> Union[Fault, ParentWallet]:
        """Loads one parent wallet into the daemon and begins synchronization"""
        if not wallet_name.endswith(".sqlite"):
            wallet_name += ".sqlite"

        path_result = self._get_wallet_path(wallet_name)
        parent_wallet = self.app_state.daemon.load_wallet(path_result, password)
        if parent_wallet is None:
            raise Fault(Errors.WALLET_NOT_LOADED_CODE,
                         Errors.WALLET_NOT_LOADED_MESSAGE)
        return parent_wallet

    def _fetch_transaction_dto(self, child_wallet: Abstract_Wallet, tx_id) -> Optional[Dict]:
        tx = child_wallet.get_transaction(tx_id).to_hex()
        if not tx:
            return
        return {"tx_hex": tx}

    def _wallet_name_available(self, wallet_name) -> bool:
        if wallet_name in self.all_wallets:
            return True
        return False

    def _check_message_size(self, message_bytes) -> None:
        if len(message_bytes) > MAX_MESSAGE_BYTES:
            raise Fault(Errors.DATA_TOO_BIG_CODE,
                         Errors.DATA_TOO_BIG_MESSAGE)

    # ----- Data transfer objects ----- #

    def _balance_dto(self, wallet) -> Dict[Any, Any]:
        confirmed_bal, unconfirmed_bal, unmatured_balance = wallet.get_balance()
        return {"confirmed_balance": confirmed_bal,
                "unconfirmed_balance": unconfirmed_bal,
                "unmatured_balance": unmatured_balance}

    def _utxo_dto(self, utxos: List[UTXO]) -> List[Dict]:
        utxos_as_dicts = []
        for utxo in utxos:
            utxos_as_dicts.append(self.utxo_as_dict(utxo))
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
                               txids: Optional[Iterable[str]]=None) -> Union[Fault, Dict[Any, Any]]:

        chain = self.app_state.daemon.network.chain()

        result = {}
        for tx_id in txids:
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

    # ----- Helpers ----- #

    async def _create_tx_helper(self, request) -> Union[Tuple, Fault]:
        vars = await self.argparser(request)
        self.raise_for_var_missing(vars, required_vars=[VNAME.WALLET_NAME, VNAME.INDEX,
                                                        VNAME.OUTPUTS])
        wallet_name = vars[VNAME.WALLET_NAME]
        index = vars[VNAME.INDEX]
        outputs = vars[VNAME.OUTPUTS]

        utxos = vars.get(VNAME.UTXOS, None)
        utxo_preselection = vars.get(VNAME.UTXO_PRESELECTION, True)
        password = vars.get(VNAME.PASSWORD, None)

        child_wallet = self._get_child_wallet(wallet_name, index)

        if not utxos:
            exclude_frozen = vars.get(VNAME.EXCLUDE_FROZEN, True)
            confirmed_only = vars.get(VNAME.CONFIRMED_ONLY, False)
            mature = vars.get(VNAME.MATURE, True)
            utxos = child_wallet.get_utxos(domain=None, exclude_frozen=exclude_frozen,
                                           confirmed_only=confirmed_only, mature=mature)

        if utxo_preselection:  # Defaults to True
            utxos = self.preselect_utxos(utxos, outputs)

        # Todo - loop.run_in_executor
        tx = child_wallet.make_unsigned_transaction(utxos, outputs, self.app_state.config)
        return tx, child_wallet, password
