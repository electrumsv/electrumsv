import json
import os
import logging
from concurrent.futures.thread import ThreadPoolExecutor
from json import JSONDecodeError
from typing import Any, cast, Dict, List, Optional, Tuple, Union

import bitcoinx
from bitcoinx import hash_to_hex_str, hex_str_to_hash, TxOutput
from aiohttp import web

from electrumsv.bitcoin import COINBASE_MATURITY
from electrumsv.coinchooser import PRNG
from electrumsv.constants import (CHANGE_SUBPATH, CredentialPolicyFlag, DATABASE_EXT,
    TransactionOutputFlag, TxFlags, unpack_derivation_path, WalletSettings)
from electrumsv.exceptions import NotEnoughFunds
from electrumsv.restapi_endpoints import ARGTYPES, HandlerUtils, VARNAMES
from electrumsv.transaction import Transaction
from electrumsv.wallet import AbstractAccount, Wallet
from electrumsv.logs import logs
from electrumsv.app_state import app_state
from electrumsv.restapi import decode_request_body, Fault, get_network_type
from electrumsv.simple_config import SimpleConfig
from electrumsv.storage import WalletStorage
from electrumsv.types import TransactionSize, Outpoint
from electrumsv.wallet_database.types import (TransactionOutputSpendableRow)
from examples.applications.restapi.constants import WalletEventNames

from .errors import Errors

logger = logging.getLogger("blockchain-support")

# P2PKH inputs and outputs only
INPUT_SIZE = 148
OUTPUT_SIZE = 34


class InsufficientCoinsError(Exception):
    pass


# Request variables
class VNAME(VARNAMES):
    AMOUNT = 'amount'
    NETWORK = 'network'
    ACCOUNT_ID = 'account_id'
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
    SPLIT_COUNT = 'split_count'
    DESIRED_UTXO_COUNT = 'desired_utxo_count'
    SPLIT_VALUE = 'split_value'
    NBLOCKS = 'nblocks'
    TX_FLAGS = 'tx_flags'

# Request types
ADDITIONAL_ARGTYPES: Dict[str, type] = {
    VNAME.NETWORK: str,
    VNAME.ACCOUNT_ID: str,
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
    VNAME.UTXO_PRESELECTION: bool,
    VNAME.AMOUNT: int,
    VNAME.SPLIT_COUNT: int,
    VNAME.DESIRED_UTXO_COUNT: int,
    VNAME.SPLIT_VALUE: int,
    VNAME.NBLOCKS: int,
    VNAME.TX_FLAGS: int,  # enum
}

ARGTYPES.update(ADDITIONAL_ARGTYPES)

HEADER_VARS = [VNAME.NETWORK, VNAME.ACCOUNT_ID, VNAME.WALLET_NAME]
BODY_VARS = [VNAME.PASSWORD, VNAME.RAWTX, VNAME.TXIDS, VNAME.UTXOS, VNAME.OUTPUTS,
             VNAME.UTXO_PRESELECTION, VNAME.REQUIRE_CONFIRMED, VNAME.EXCLUDE_FROZEN,
             VNAME.CONFIRMED_ONLY, VNAME.MATURE, VNAME.AMOUNT, VNAME.SPLIT_COUNT,
             VNAME.DESIRED_UTXO_COUNT, VNAME.SPLIT_VALUE, VNAME.NBLOCKS, VNAME.TX_FLAGS]


class ExtendedHandlerUtils(HandlerUtils):
    """Extends ElectrumSV HandlerUtils"""

    MAX_WORKERS = 1

    def __init__(self):
        super().__init__()
        self.logger = logs.get_logger("ext-handler-utils")
        self.wallets_path = os.path.join(app_state.config.electrum_path(), "wallets")
        self.all_wallets = self._get_all_wallets(self.wallets_path)
        self.app_state = app_state  # easier to monkeypatch for testing
        self.prev_transaction = ''
        self.txb_executor = ThreadPoolExecutor(max_workers=self.MAX_WORKERS,
                                               thread_name_prefix='txb_executor')

    # ---- Parse Header and Body variables ----- #

    def raise_for_rawtx_size(self, rawtx):
        if (len(rawtx) / 2) > 99000:
            fault = Fault(Errors.DATA_TOO_BIG_CODE, Errors.DATA_TOO_BIG_MESSAGE)
            raise fault

    def raise_for_var_missing(self, vars, required_vars: List[str]):
        for varname in required_vars:
            if vars.get(varname) is None:
                if varname in HEADER_VARS:
                    raise Fault(Errors.GENERIC_BAD_REQUEST_CODE,
                                Errors.HEADER_VAR_NOT_PROVIDED_MESSAGE.format(varname))
                else:
                    raise Fault(Errors.GENERIC_BAD_REQUEST_CODE,
                                Errors.BODY_VAR_NOT_PROVIDED_MESSAGE.format(varname))

    def raise_for_type_okay(self, vars):
        for vname in vars:
            if vars.get(vname, None):
                if not ARGTYPES.get(vname):
                    message = f"'{vname}' is not a supported type"
                    raise Fault(Errors.GENERIC_BAD_REQUEST_CODE, message)
                if not isinstance(vars.get(vname), ARGTYPES.get(vname)):
                    message = f"{vars.get(vname)} must be of type: '{ARGTYPES.get(vname)}'"
                    raise Fault(Errors.GENERIC_BAD_REQUEST_CODE, message)

    def account_id_if_isdigit(self, index: str) -> Union[int, Fault]:
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

    async def argparser(self, request: web.Request, required_vars: List=None,
            check_wallet_availability=True) -> Dict[str, Any]:
        """Extracts and checks all standardized header and body variables from the request object
        as a dictionary to feed to the handlers."""
        vars: Dict = {}
        header_vars = self.get_header_vars(request)
        body_vars = await self.get_body_vars(request)
        vars.update(header_vars)
        vars.update(body_vars)
        self.raise_for_type_okay(vars)

        wallet_name = vars.get(VNAME.WALLET_NAME)
        if wallet_name and check_wallet_availability:
            self.raise_for_wallet_availability(wallet_name)

        account_id = vars.get(VNAME.ACCOUNT_ID)
        if account_id:
            vars[VNAME.ACCOUNT_ID] = self.account_id_if_isdigit(account_id)

        outputs = vars.get(VNAME.OUTPUTS)
        if outputs:
            vars[VNAME.OUTPUTS] = self.outputs_from_dicts(outputs)

        utxos = vars.get(VNAME.UTXOS)
        if utxos:
            vars[VNAME.UTXOS] = self.utxokeys_from_list(utxos)

        if required_vars:
            self.raise_for_var_missing(vars, required_vars)

        return vars

    # ----- Support functions ----- #

    def utxo_as_dict(self, utxo: TransactionOutputSpendableRow):
        return {"value": utxo.value,
                "script_type": utxo.script_type,
                "tx_hash": hash_to_hex_str(utxo.tx_hash),
                "out_index": utxo.txo_index,
                "keyinstance_id": utxo.keyinstance_id,
                "is_coinbase": utxo.flags & TransactionOutputFlag.COINBASE != 0,
                "flags": utxo.flags}  # TransactionOutputFlag(s) only

    def outputs_from_dicts(self, outputs: Optional[List[Dict[str, Any]]]) -> List[TxOutput]:
        outputs_from_dicts = []
        for output in outputs:
            spk = bitcoinx.Script.from_hex(output.get('script_pubkey'))
            outputs_from_dicts.append(bitcoinx.TxOutput(value=output.get('value'),
                                                        script_pubkey=spk))
        return outputs_from_dicts

    def utxokeys_from_list(self, entries: List[Tuple[str, int]]) -> List[Outpoint]:
        return [
            Outpoint(bitcoinx.hex_str_to_hash(tx_id), txo_index)
            for (tx_id, txo_index) in entries
        ]

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
            raise Fault(Errors.BAD_WALLET_NAME_CODE, Errors.BAD_WALLET_NAME_MESSAGE)
        if os.path.exists(wallet_path):
            return wallet_path
        else:
            raise Fault(Errors.WALLET_NOT_FOUND_CODE, Errors.WALLET_NOT_FOUND_MESSAGE)

    def _get_all_wallets(self, wallets_path) -> List[str]:
        """returns all parent wallet paths"""
        all_parent_wallets = []
        for item in os.listdir(wallets_path):
            if item.endswith("-shm") or item.endswith("-wal"):
                continue
            else:
                all_parent_wallets.append(item)
        return sorted(all_parent_wallets)

    def _get_parent_wallet(self, wallet_name: str) -> Wallet:
        """returns a child wallet object"""
        path_result = self._get_wallet_path(wallet_name)
        parent_wallet = self.app_state.daemon.get_wallet(path_result)
        if not parent_wallet:
            message = Errors.LOAD_BEFORE_GET_MESSAGE.format(get_network_type(),
                                                            'wallet_name.sqlite')
            raise Fault(code=Errors.LOAD_BEFORE_GET_CODE, message=message)
        return parent_wallet

    def _get_account(self, wallet_name: str, account_id: int=1) -> AbstractAccount:
        parent_wallet = self._get_parent_wallet(wallet_name=wallet_name)
        child_wallet = parent_wallet.get_account(account_id)
        if child_wallet is None:
            message = f"There is no account at account_id: {account_id}."
            raise Fault(Errors.WALLET_NOT_FOUND_CODE, message)
        return child_wallet

    def _is_wallet_ready(self, wallet_name: Optional[str]=None) -> bool:
        wallet = self._get_parent_wallet(wallet_name)
        return wallet.is_synchronized()

    async def _load_wallet(self, wallet_name: str, wallet_password: str) -> Wallet:
        """Loads one parent wallet into the daemon and begins synchronization"""
        wallet_name = WalletStorage.canonical_path(wallet_name)

        path_result = self._get_wallet_path(wallet_name)
        wallet = self.app_state.daemon.get_wallet(path_result)
        # If wallet is not already loaded - register for websocket events and allow gap limit
        # adjustments for faster synchronization with high tx throughput. However, gap limit
        # scanning should become less relevant as wallet matures to 'true SPV' and merchant API use.
        # multiple change addresses is preferred for privacy and keeping utxo set granular
        if wallet is None:
            self.network = self.app_state.daemon.network

            app_state.credentials.set_wallet_password(path_result, wallet_password,
                CredentialPolicyFlag.FLUSH_AFTER_WALLET_LOAD)

            wallet = self.app_state.daemon.load_wallet(path_result)
            if wallet is None:
                raise Fault(Errors.WALLET_NOT_LOADED_CODE, Errors.WALLET_NOT_LOADED_MESSAGE)

            wallet.register_callback(app_state.app.on_triggered_event,
                [WalletEventNames.TRANSACTION_STATE_CHANGE, WalletEventNames.TRANSACTION_ADDED,
                    WalletEventNames.VERIFIED])
            wallet.set_boolean_setting(WalletSettings.USE_CHANGE, True)
            wallet.set_boolean_setting(WalletSettings.MULTIPLE_CHANGE, True)

        return wallet

    def _fetch_transaction_dto(self, account: AbstractAccount, tx_id) -> Optional[Dict]:
        tx_hash = hex_str_to_hash(tx_id)
        tx_bytes = account._wallet.get_transaction_bytes(tx_hash)
        if tx_bytes is None:
            raise Fault(Errors.TRANSACTION_NOT_FOUND_CODE, Errors.TRANSACTION_NOT_FOUND_MESSAGE)
        return {"tx_hex": tx_bytes.hex()}

    def _wallet_name_available(self, wallet_name) -> bool:
        available_wallet_names = self._get_all_wallets(self.wallets_path)
        if wallet_name in available_wallet_names:
            return True
        return False

    def script_type_repr(self, int):
        mappings = {
            0: 'NONE',
            1: 'COINBASE',
            2: 'P2PKH',
            3: 'P2PK',
            4: 'MULTISIG_P2SH',
            5: 'MULTISIG_BARE',
            6: 'MULTISIG_ACCUMULATOR'
        }
        return mappings[int]

    async def send_request(self, method, args):
        session = await self.app_state.daemon.network._main_session()
        return await session.send_request(method, args)

    def preselect_utxos(self, utxos: List[TransactionOutputSpendableRow], outputs, batch_size=10) \
            -> List[TransactionOutputSpendableRow]:
        """Inexact, random pre-selectiion of utxos for performance reasons.
        'make_unsigned_transaction' is slow if it iterates over all utxos.
        - Disabled via {'utxo_preselection': False} in body of request."""
        BATCH_SIZE = batch_size
        if len(utxos) <= BATCH_SIZE:
            return utxos  # abort

        selected_utxos = []
        # Deterministic randomness from coins (only select first 10 (or batch_size) for speed)
        p = PRNG(b''.join(sorted(utxo.tx_hash for utxo in utxos[0:BATCH_SIZE])))

        tx = Transaction.from_io([], outputs)
        # Size of the transaction with no inputs and no change
        base_size = sum(tx.estimated_size())
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

    # ----- Data transfer objects ----- #

    def _balance_dto(self, wallet: AbstractAccount) -> Dict[Any, Any]:
        wallet_balance = wallet.get_balance()
        return {"confirmed_balance": wallet_balance.confirmed,
                "unconfirmed_balance": wallet_balance.unconfirmed,
                "unmatured_balance": wallet_balance.unmatured,
                "allocated_balance": wallet_balance.allocated}

    def _utxo_dto(self, utxos: List[TransactionOutputSpendableRow]) -> List[Dict]:
        utxos_as_dicts = []
        for utxo in utxos:
            utxos_as_dicts.append(self.utxo_as_dict(utxo))
        return utxos_as_dicts

    def _history_dto(self, account: AbstractAccount, tx_flags: Optional[TxFlags]=None) \
            -> List[Dict[Any, Any]]:
        result = []
        entries = account.get_transaction_value_entries(mask=tx_flags)
        for entry in entries:
            result.append({"txid": hash_to_hex_str(entry.tx_hash),
                           "height": entry.block_height,
                           "tx_flags": entry.flags,
                           "value": entry.value})
        return result

    def _account_dto(self, account) -> Dict[Any, Any]:
        """child wallet data transfer object"""
        script_type = account._row.default_script_type

        # TODO Strictly speaking `is_wallet_ready` really only applies to the whole wallet and
        #   not this
        return {account._id: {"wallet_type": account._row.account_name,
                             "default_script_type": self.script_type_repr(script_type),
                             "is_wallet_ready": account._wallet.is_synchronized()}}

    def _accounts_dto(self, wallet: Wallet):
        """child wallets data transfer object"""
        accounts = {}
        for account in wallet.get_accounts():
            accounts.update(self._account_dto(account))
        return accounts

    def _coin_state_dto(self, account) -> Union[Fault, Dict[str, Any]]:
        all_coins = account.get_transaction_outputs_with_key_and_tx_data(confirmed_only=False,
            mature=False)
        unmatured_coins = []
        cleared_coins = []
        settled_coins = []

        for coin in all_coins:
            if coin.flags & TransactionOutputFlag.COINBASE:
                if coin.block_height + COINBASE_MATURITY > account._wallet.get_local_height():
                    unmatured_coins.append(coin)
                    continue
            if coin.tx_flags & TxFlags.STATE_SETTLED:
                settled_coins.append(coin)
            elif coin.tx_flags & TxFlags.STATE_CLEARED:
                cleared_coins.append(coin)

        return {"cleared_coins": len(cleared_coins),
                "settled_coins": len(settled_coins),
                "unmatured_coins": len(unmatured_coins)}

    # ----- Helpers ----- #

    async def _create_tx_helper(self, request) -> Tuple[Transaction, AbstractAccount, str]:
        try:
            vars = await self.argparser(request)
            self.raise_for_var_missing(vars, required_vars=[VNAME.WALLET_NAME, VNAME.ACCOUNT_ID,
                                                            VNAME.OUTPUTS, VNAME.PASSWORD])
            wallet_name = vars[VNAME.WALLET_NAME]
            index = vars[VNAME.ACCOUNT_ID]
            # TODO(REST-API-FINALISATION) this should pass in ids and lookup values
            outputs = vars[VNAME.OUTPUTS]

            # TODO(REST-API-FINALISATION) this should pass in ids and lookup values
            utxos = cast(Optional[List[TransactionOutputSpendableRow]], vars.get(VNAME.UTXOS, None))
            utxo_preselection = vars.get(VNAME.UTXO_PRESELECTION, True)
            password = vars.get(VNAME.PASSWORD, None)
            assert password is not None

            account = self._get_account(wallet_name, index)

            if not utxos:
                exclude_frozen = vars.get(VNAME.EXCLUDE_FROZEN, False)
                confirmed_only = vars.get(VNAME.CONFIRMED_ONLY, False)
                mature = vars.get(VNAME.MATURE, True)
                utxos = account.get_transaction_outputs_with_key_data(exclude_frozen=exclude_frozen,
                    confirmed_only=confirmed_only, mature=mature)

            if utxo_preselection:  # Defaults to True
                utxos = self.preselect_utxos(utxos, outputs)

            # Todo - loop.run_in_executor
            tx, tx_context = account.make_unsigned_transaction(utxos, outputs)
            self.raise_for_duplicate_tx(tx)
            future = account.sign_transaction(tx, password, tx_context)
            if future is not None:
                future.result()
            return tx, account, password
        except NotEnoughFunds:
            raise Fault(Errors.INSUFFICIENT_COINS_CODE, Errors.INSUFFICIENT_COINS_MESSAGE)

    async def _broadcast_transaction(self, rawtx: str, tx_hash: bytes, account: AbstractAccount):
        result = await self.send_request('blockchain.transaction.broadcast', [rawtx])
        account.maybe_set_transaction_state(tx_hash, TxFlags.STATE_CLEARED,
            TxFlags.MASK_STATE_BROADCAST)
        self.logger.debug("successful broadcast for %s", result)
        return result

    def remove_transaction(self, tx_hash: bytes, account: AbstractAccount) -> None:
        # removal of txs that are not in the STATE_SIGNED tx state is disabled for now as it may
        # cause issues with expunging utxos inadvertently.
        tx_flags = account._wallet.get_transaction_flags(tx_hash)
        is_signed_state = (tx_flags & TxFlags.STATE_SIGNED) == TxFlags.STATE_SIGNED
        # Todo - perhaps remove restriction to STATE_SIGNED only later (if safe for utxos state)
        if not is_signed_state:
            raise Fault(Errors.DISABLED_FEATURE_CODE, Errors.DISABLED_FEATURE_MESSAGE)
        account._wallet.remove_transaction(tx_hash)

    def select_inputs_and_outputs(self, config: SimpleConfig,
            account: AbstractAccount,
            base_fee: int,
            split_count: int = 50,
            split_value: int = 10000,
            desired_utxo_count: int = 2000,
            max_utxo_margin: int = 200,
            require_confirmed: bool = True,
            ) -> Union[Tuple[List[TransactionOutputSpendableRow], List[TxOutput], bool], Fault]:

        INPUT_COST = config.estimate_fee(TransactionSize(INPUT_SIZE, 0))
        OUTPUT_COST = config.estimate_fee(TransactionSize(OUTPUT_SIZE, 0))
        all_coins = account.get_transaction_outputs_with_key_data(exclude_frozen=True, mature=True)

        # adds extra inputs as required to meet the desired utxo_count.
        # Ignore coins that are too expensive to send, or not confirmed.
        # Todo - this is inefficient to iterate over all coins (need better handling of dust utxos)
        if require_confirmed:
            get_metadata = account.get_transaction_metadata
            spendable_coins = [coin for coin in all_coins
                if coin.value > (INPUT_COST + OUTPUT_COST)
                and get_metadata(coin.tx_hash).height > 0]
        else:
            spendable_coins = [coin for coin in all_coins if
                                coin.value > (INPUT_COST + OUTPUT_COST)]

        inputs = []
        outputs = []
        selection_value = base_fee
        attempted_split = False
        if len(all_coins) < desired_utxo_count:
            attempted_split = True
            split_count = min(split_count,
                                desired_utxo_count - len(all_coins) + max_utxo_margin)

            # Increase the transaction cost for the additional required outputs.
            selection_value += split_count * OUTPUT_COST + split_count * split_value

            # Collect sufficient inputs to cover the output value.
            # highest value coins first for splitting
            ordered_coins = sorted(spendable_coins, key=lambda k: k.value, reverse=True)
            for coin in ordered_coins:
                inputs.append(coin)
                if sum(input.value for input in inputs) >= selection_value:
                    break
                # Increase the transaction cost for the additional required input.
                selection_value += INPUT_COST

            if len(inputs):
                # We ensure that we do not use conflicting addresses for the split outputs by
                # explicitly generating the addresses we are splitting to.
                for key in account.get_fresh_keys(CHANGE_SUBPATH, count=split_count):
                    derivation_path = unpack_derivation_path(key.derivation_data2)
                    pubkey = account.derive_pubkeys(derivation_path)
                    outputs.append(TxOutput(split_value, pubkey.P2PKH_script()))
                return inputs, outputs, attempted_split

        for coin in spendable_coins:
            inputs.append(coin)
            if sum(input.value for input in inputs) >= selection_value:
                break
            # Increase the transaction cost for the additional required input.
            selection_value += INPUT_COST
        else:
            # We failed to collect enough inputs to cover the outputs.
            raise InsufficientCoinsError

        return inputs, outputs, attempted_split

    def cleanup_tx(self, tx, account):
        """Use of the frozen utxo mechanic may be phased out because signing a tx allocates the
        utxos thus making freezing redundant."""
        self.remove_transaction(tx.hash(), account)

    def batch_response(self, response: Dict) -> web.Response:
        # follows this spec https://opensource.zalando.com/restful-api-guidelines/#152
        return web.Response(text=json.dumps(response, indent=2), content_type="application/json",
                            status=207)

    def check_if_wallet_exists(self, file_path):
        if os.path.exists(file_path):
            raise Fault(code=Errors.BAD_WALLET_NAME_CODE,
                        message=f"'{file_path + DATABASE_EXT}' already exists")

        if not file_path.endswith(DATABASE_EXT):
            if os.path.exists(file_path + DATABASE_EXT):
                raise Fault(code=Errors.BAD_WALLET_NAME_CODE,
                            message=f"'{file_path + DATABASE_EXT}' already exists")