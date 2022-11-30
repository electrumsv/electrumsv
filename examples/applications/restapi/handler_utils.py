import enum
import json
import os
import logging
from concurrent.futures.thread import ThreadPoolExecutor
from json import JSONDecodeError
from typing import Any, cast, Dict, List, Optional, Sequence, Tuple, Union

import bitcoinx
from bitcoinx import hash_to_hex_str, hex_str_to_hash, TxOutput
from aiohttp import web

from electrumsv.bitcoin import COINBASE_MATURITY
from electrumsv.coinchooser import PRNG
from electrumsv.constants import (CHANGE_SUBPATH, CredentialPolicyFlag, DATABASE_EXT,
    TransactionOutputFlag, TxFlags, unpack_derivation_path, WalletSettings)
from electrumsv.exceptions import NotEnoughFunds

# TODO(1.4.0) RESTAPI. Decide what to do with these imports
# from electrumsv.restapi_endpoints import ARGTYPES, VARNAMES
from electrumsv.transaction import Transaction
from electrumsv.wallet import AbstractAccount, Wallet
from electrumsv.logs import logs
from electrumsv.app_state import app_state
from electrumsv.simple_config import SimpleConfig
from electrumsv.storage import WalletStorage
from electrumsv.types import TransactionSize, Outpoint
from electrumsv.wallet_database.types import TransactionRow, TransactionOutputSpendableRow
from examples.applications.restapi.constants import WalletEventNames

from .errors import Errors

logger = logging.getLogger("blockchain-support")

# P2PKH inputs and outputs only
INPUT_SIZE = 148
OUTPUT_SIZE = 34


class InsufficientCoinsError(Exception):
    pass


# Request variables
class VNAME:
    AMOUNT = 'amount'
    NETWORK = 'network'
    ACCOUNT_ID = 'account_id'
    WALLET_INSTANCE_ID = 'wallet_instance_id'
    WALLET_ID = 'wallet_id'
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
    MESSAGE = 'message'

# Request types
ADDITIONAL_ARGTYPES: Dict[str, type] = {
    VNAME.NETWORK: str,
    VNAME.ACCOUNT_ID: str,
    VNAME.WALLET_INSTANCE_ID: int,
    VNAME.WALLET_NAME: str,
    VNAME.WALLET_ID: str,
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
    VNAME.MESSAGE: str,
}

# TODO(1.4.0) RESTAPI. Decide what to do with this - remove? keep?
# ARGTYPES.update(ADDITIONAL_ARGTYPES)

ROUTE_VARS = [VNAME.NETWORK, VNAME.ACCOUNT_ID, VNAME.WALLET_NAME, VNAME.WALLET_ID]
BODY_VARS = [VNAME.PASSWORD, VNAME.RAWTX, VNAME.TXIDS, VNAME.UTXOS, VNAME.OUTPUTS,
             VNAME.UTXO_PRESELECTION, VNAME.REQUIRE_CONFIRMED, VNAME.EXCLUDE_FROZEN,
             VNAME.CONFIRMED_ONLY, VNAME.MATURE, VNAME.AMOUNT, VNAME.SPLIT_COUNT,
             VNAME.DESIRED_UTXO_COUNT, VNAME.SPLIT_VALUE, VNAME.NBLOCKS, VNAME.TX_FLAGS,
             VNAME.MESSAGE]


class WalletInstanceKind(enum.IntEnum):
    TEST_MINING = 1
    TEST_PAYMENT = 2

WalletInstancePaths: Dict[Union[int, WalletInstanceKind], str] = {
    WalletInstanceKind.TEST_MINING:
        os.path.join("contrib", "functional_tests", "data", "wallet_mining.sqlite"),
    WalletInstanceKind.TEST_PAYMENT:
        os.path.join("contrib", "functional_tests", "data", "wallet_payment.sqlite"),
}


class ExtendedHandlerUtils:
    MAX_WORKERS = 1

    def __init__(self):
        super().__init__()
        self.logger = logs.get_logger("ext-handler-utils")
        self.wallets_path = os.path.join(app_state.config.electrum_path(), "wallets")
        if os.path.exists(self.wallets_path):
            self.all_wallets = self._get_all_wallets(self.wallets_path)
        else:
            self.all_wallets = []
        self.app_state = app_state  # easier to monkeypatch for testing
        self.prev_transaction = ''
        self.txb_executor = ThreadPoolExecutor(max_workers=self.MAX_WORKERS,
                                               thread_name_prefix='txb_executor')

    # ---- Parse Header and Body variables ----- #

    def raise_for_var_missing(self, vars, required_vars: List[str]) -> None:
        for varname in required_vars:
            if vars.get(varname) is None:
                if varname in ROUTE_VARS:
                    raise web.HTTPBadRequest(reason=f"Missing routing variable {varname}")
                raise web.HTTPBadRequest(reason=f"Missing body variable {varname}")

    def raise_for_type_okay(self, vars) -> None:
        for vname in vars:
            value = vars[vname]
            if not value:
                continue
            if vname not in ARGTYPES:
                message = f"'{vname}' is not a supported type"
                raise web.HTTPBadRequest(reason=message)
            if not isinstance(value, ARGTYPES[vname]):
                message = f"{value} must be of type: '{ARGTYPES[vname]}'"
                raise web.HTTPBadRequest(reason=message)

    def account_id_if_isdigit(self, index: str) -> int:
        if not index.isdigit():
            message = "child wallet index in url must be an integer. You tried " \
                      "index='%s'." % index
            raise web.HTTPBadRequest(reason=message)
        return int(index)

    def raise_for_wallet_availability(self, wallet_name: str) -> str:
        if not self._wallet_name_available(wallet_name):
            raise web.HTTPNotFound(reason=f"Wallet '{wallet_name}' not found")
        return wallet_name

    def get_route_vars(self, request: web.Request) -> dict[str, Any]:
        # This gets the variables embedded implicitly in the path for any given handler.
        routing_variables: dict[str, Any] = {}
        for varname in ROUTE_VARS:
            routing_variables.update({varname: request.match_info.get(varname)})
        return routing_variables

    async def argparser(self, request: web.Request, required_vars: Optional[List]=None,
            check_wallet_availability: bool=True) -> Dict[str, Any]:
        """Extracts and checks all standardized header and body variables from the request object
        as a dictionary to feed to the handlers."""
        vars: Dict = {}
        header_vars = self.get_route_vars(request)
        try:
            body_vars = cast(dict[str, Any], await request.json())
        except JSONDecodeError:
            raise web.HTTPBadRequest(reason="JSON request body appears corrupt")
        vars.update(header_vars)
        vars.update(body_vars)
        self.raise_for_type_okay(vars)

        wallet_name = vars.get(VNAME.WALLET_NAME)
        if wallet_name and check_wallet_availability:
            self.raise_for_wallet_availability(wallet_name)

        wallet_id = vars.get(VNAME.WALLET_ID)
        if wallet_id:
            vars[VNAME.WALLET_ID] = self.account_id_if_isdigit(wallet_id)

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

    def utxo_as_dict(self, utxo: TransactionOutputSpendableRow) -> Dict[str, Any]:
        return {"value": utxo.value,
                "script_type": utxo.script_type,
                "tx_hash": hash_to_hex_str(utxo.tx_hash),
                "out_index": utxo.txo_index,
                "keyinstance_id": utxo.keyinstance_id,
                "is_coinbase": utxo.flags & TransactionOutputFlag.COINBASE != 0,
                "flags": utxo.flags}  # TransactionOutputFlag(s) only

    def outputs_from_dicts(self, outputs: List[Dict[str, Any]]) -> List[TxOutput]:
        outputs_from_dicts = []
        for output in outputs:
            spk = bitcoinx.Script.from_hex(output['script_pubkey'])
            outputs_from_dicts.append(bitcoinx.TxOutput(value=output['value'],
                                                        script_pubkey=spk))
        return outputs_from_dicts

    def utxokeys_from_list(self, entries: List[Tuple[str, int]]) -> List[Outpoint]:
        return [
            Outpoint(bitcoinx.hex_str_to_hash(tx_id), txo_index)
            for (tx_id, txo_index) in entries
        ]

    def raise_for_duplicate_tx(self, tx: Transaction) -> None:
        """because the network can be very slow to give this important feedback and instead will
        return the txid as an http 200 response."""
        if tx.txid() == self.prev_transaction:
            message = "You've already sent this transaction: {}".format(tx.txid())
            raise web.HTTPBadRequest(reason=message)

    def _get_wallet_path(self, wallet_name: str, is_relative: bool=True) -> str:
        """returns parent wallet path. The wallet_name must include .sqlite extension"""
        if is_relative:
            wallet_path = os.path.join(self.wallets_path, wallet_name)
            wallet_path = os.path.normpath(wallet_path)
            if wallet_name != os.path.basename(wallet_path):
                raise web.HTTPBadRequest(reason=Errors.BAD_WALLET_NAME_MESSAGE)
        else:
            if not os.path.isabs(wallet_name):
                raise web.HTTPNotFound(reason=Errors.WALLET_NOT_FOUND_MESSAGE)
            wallet_path = wallet_name
        if os.path.exists(wallet_path):
            return wallet_path
        raise web.HTTPNotFound(reason=Errors.WALLET_NOT_FOUND_MESSAGE)

    def _get_all_wallets(self, wallets_path: str) -> list[str]:
        """returns all parent wallet paths"""
        # This is called on startup and the wallets directory may not exist if no wallets have
        # been created yet, i.e. "electrum-sv create_wallet <wallet-name>" was not executed.
        assert os.path.exists(wallets_path)

        all_parent_wallets = []
        for item in os.listdir(wallets_path):
            if item.endswith("-shm") or item.endswith("-wal"):
                continue
            all_parent_wallets.append(item)
        return sorted(all_parent_wallets)

    def _get_parent_wallet(self, wallet_name: str) -> Wallet:
        """returns a child wallet object"""
        resolved_wallet_path = self._get_wallet_path(wallet_name)
        wallet = self.app_state.daemon.get_wallet(resolved_wallet_path)
        if wallet is None:
            raise web.HTTPBadRequest(reason="Wallet not loaded")
        return wallet

    def _get_wallet_by_id(self, wallet_id: int) -> Wallet:
        """returns the wallet object"""
        wallet = self.app_state.daemon.get_wallet_by_id(wallet_id)
        if wallet is None:
            raise web.HTTPBadRequest(reason="Wallet not loaded")
        return wallet

    def _get_account(self, wallet_name: str, account_id: int=1) -> AbstractAccount:
        wallet = self._get_parent_wallet(wallet_name=wallet_name)
        account = wallet.get_account(account_id)
        if account is None:
            raise web.HTTPBadRequest(reason=f"Invalid account id '{account_id}'")
        return account

    def _get_account_from_wallet(self, wallet: Wallet, account_id: int=1) -> AbstractAccount:
        account = wallet.get_account(account_id)
        if account is None:
            raise web.HTTPBadRequest(reason=f"Invalid account id '{account_id}'")
        return account

    async def _load_wallet(self, wallet_name: str, wallet_password: str,
            enforce_wallet_directory: bool=True) -> Wallet:
        """Loads one parent wallet into the daemon and begins synchronization"""
        wallet_name = WalletStorage.canonical_path(wallet_name)

        path_result = self._get_wallet_path(wallet_name, is_relative=enforce_wallet_directory)
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
                raise web.HTTPBadRequest(reason="Wallet not loaded")

            wallet.events.register_callback(app_state.app.on_triggered_event,
                [WalletEventNames.TRANSACTION_STATE_CHANGE, WalletEventNames.TRANSACTION_ADDED,
                    WalletEventNames.VERIFIED])
            wallet.set_boolean_setting(WalletSettings.USE_CHANGE, True)
            wallet.set_boolean_setting(WalletSettings.MULTIPLE_CHANGE, True)

        return wallet

    def _fetch_transaction_dto(self, account: AbstractAccount, tx_id) -> Dict[str, Any]:
        tx_hash = hex_str_to_hash(tx_id)
        tx_bytes = account._wallet.data.get_transaction_bytes(tx_hash)
        if tx_bytes is None:
            raise web.HTTPNotFound(reason="Transaction not found")
        return {"tx_hex": tx_bytes.hex()}

    def _wallet_name_available(self, wallet_name) -> bool:
        available_wallet_names = self._get_all_wallets(self.wallets_path)
        if wallet_name in available_wallet_names:
            return True
        return False

    def script_type_repr(self, int) -> str:
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

    async def send_request(self, method: str, args: Sequence[Any]) -> Any:
        assert self.app_state.daemon.network is not None
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
            total_size = TransactionSize(
                sum(INPUT_SIZE for utxo in selected_utxos) + base_size + CHANGE_SAFE_MARGIN, 0)
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

    def _balance_dto(self, wallet: AbstractAccount) -> Dict[str, Any]:
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
            -> List[Dict[str, Any]]:
        result: List[Dict[str, Any]] = []
        entries = account.get_transaction_value_entries(mask=tx_flags)
        for entry in entries:
            result.append({"txid": hash_to_hex_str(entry.tx_hash),
                           "block_hash": entry.block_hash,
                           "tx_flags": entry.flags,
                           "value": entry.value})
        return result

    def _account_dto(self, account) -> Dict[int, Dict[str, Any]]:
        """child wallet data transfer object"""
        script_type = account._row.default_script_type

        # TODO Strictly speaking `is_wallet_ready` really only applies to the whole wallet and
        #   not this
        return {account._id: {"wallet_type": account._row.account_name,
                             "default_script_type": self.script_type_repr(script_type),
                             "is_wallet_ready": account._wallet.is_synchronized()}}

    def _accounts_dto(self, wallet: Wallet) -> Dict[int, Dict[str, Any]]:
        """child wallets data transfer object"""
        accounts: Dict[int, Dict[str, Any]] = {}
        for account in wallet.get_accounts():
            accounts.update(self._account_dto(account))
        return accounts

    def _coin_state_dto(self, account) -> Dict[str, Any]:
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
            raise web.HTTPBadRequest(reason="Insufficient coins")

    async def _broadcast_transaction(self, rawtx: str, tx_hash: bytes, account: AbstractAccount):
        result = await self.send_request('blockchain.transaction.broadcast', [rawtx])
        await account._wallet.data.set_transaction_state_async(tx_hash, TxFlags.STATE_CLEARED,
            TxFlags.MASK_STATE_BROADCAST)
        self.logger.debug("successful broadcast for %s", result)
        return result

    def remove_transaction(self, tx_hash: bytes, account: AbstractAccount) -> None:
        # removal of txs that are not in the STATE_SIGNED tx state is disabled for now as it may
        # cause issues with expunging utxos inadvertently.
        tx_flags = account._wallet.data.get_transaction_flags(tx_hash)
        assert tx_flags is not None
        is_signed_state = (tx_flags & TxFlags.STATE_SIGNED) == TxFlags.STATE_SIGNED
        # Todo - perhaps remove restriction to STATE_SIGNED only later (if safe for utxos state)
        if not is_signed_state:
            raise web.HTTPBadRequest(reason="Disabled feature")
        account._wallet.remove_transaction(tx_hash)

    def select_inputs_and_outputs(self, config: SimpleConfig,
            account: AbstractAccount,
            base_fee: int,
            split_count: int = 50,
            split_value: int = 10000,
            desired_utxo_count: int = 2000,
            max_utxo_margin: int = 200,
            require_confirmed: bool = True,
            ) -> Tuple[list[TransactionOutputSpendableRow], list[TxOutput], bool]:

        INPUT_COST = config.estimate_fee(TransactionSize(INPUT_SIZE, 0))
        OUTPUT_COST = config.estimate_fee(TransactionSize(OUTPUT_SIZE, 0))
        all_coins = account.get_transaction_outputs_with_key_data(exclude_frozen=True, mature=True)

        # adds extra inputs as required to meet the desired utxo_count.
        # Ignore coins that are too expensive to send, or not confirmed.
        # Todo - this is inefficient to iterate over all coins (need better handling of dust utxos)
        if require_confirmed:
            read_transaction = account._wallet.data.read_transaction
            spendable_coins = [coin for coin in all_coins
                if coin.value > (INPUT_COST + OUTPUT_COST)
                and cast(TransactionRow, read_transaction(coin.tx_hash)).block_hash is not None]
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
                    assert key.derivation_data2 is not None
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

    def cleanup_tx(self, tx: Transaction, account: AbstractAccount) -> None:
        """Use of the frozen utxo mechanic may be phased out because signing a tx allocates the
        utxos thus making freezing redundant."""
        self.remove_transaction(tx.hash(), account)

    def batch_response(self, response: Dict[str, Any]) -> web.Response:
        # follows this spec https://opensource.zalando.com/restful-api-guidelines/#152
        return web.Response(text=json.dumps(response, indent=2), content_type="application/json",
                            status=207)

    def check_if_wallet_exists(self, file_path: str) -> None:
        if os.path.exists(file_path):
            raise web.HTTPBadRequest(reason="Wallet already exists")

        if not file_path.endswith(DATABASE_EXT):
            if os.path.exists(file_path + DATABASE_EXT):
                raise web.HTTPBadRequest(reason="Wallet already exists")
