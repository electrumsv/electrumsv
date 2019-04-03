import base64
import enum
import jsonrpclib
import os
from typing import Optional, Tuple, List

import aiorpcx

from electrumsv.app_state import app_state
from electrumsv.address import ScriptOutput
from electrumsv.bitcoin import TYPE_SCRIPT, TYPE_ADDRESS
from electrumsv.crypto import sha256d
from electrumsv.logs import logs
from electrumsv.transaction import Transaction
from electrumsv.wallet import Abstract_Wallet


class RPCError(Exception):
    pass



class FileProtocol(enum.IntEnum):
    B = 1
    Bcat = 2


# All RPC arguments are keyword arguments for a reason.


class LocalRPCFunctions:
    def __init__(self) -> None:
        self._logger = logs.get_logger("local-rpc")

    def _get_wallet_path(self, wallet_name: str) -> str:
        esv_wallets_dir = os.path.join(app_state.config.electrum_path(), "wallets")
        wallet_path = os.path.join(esv_wallets_dir, wallet_name)
        wallet_path = os.path.normpath(wallet_path)
        if wallet_name != os.path.basename(wallet_path):
            raise RPCError("wallet_name must not be a path")
        if not os.path.exists(wallet_path):
            raise RPCError(f"{wallet_path}: wallet_name does not exist")
        return wallet_path

    def _get_wallet(self, wallet_name: str) -> Abstract_Wallet:
        if type(wallet_name) is not str:
            raise RPCError("wallet_name is not a string")
        wallet_path = self._get_wallet_path(wallet_name)
        wallet = app_state.daemon.get_wallet(wallet_path)
        if wallet is None:
            raise RPCError("wallet_name not loaded")
        return wallet

    def load_wallet(self, wallet_name: Optional[str]=None, password: Optional[str]=None) -> None:
        wallet_path = self._get_wallet_path(wallet_name)
        wallet = app_state.daemon.load_wallet(wallet_path, password)
        return wallet is not None

    def unload_wallet(self, wallet_name: Optional[str]=None) -> None:
        wallet_path = self._get_wallet_path(wallet_name)
        app_state.daemon.stop_wallet_at_path(wallet_path)

    def get_balance(self, wallet_name: Optional[str]=None) -> Tuple[int, int, int]:
        try:
            wallet = self._get_wallet(wallet_name)
        except RPCError as e:
            raise RPCError(str(e))
        return wallet.get_balance()

    def split_coins(self, wallet_name: Optional[str]=None, password: Optional[str]=None,
            coin_count: Optional[int]=25) -> str:
        wallet = self._get_wallet(wallet_name)

        confirmed_coins = wallet.get_spendable_coins(None, {'confirmed_only': True})
        if len(confirmed_coins) > 3:
            return jsonrpclib.Fault(50, "confirmed-coins-exist", len(confirmed_coins))

        all_coins = wallet.get_spendable_coins(None, {})
        confirmed_coins = list(c for c in all_coins if c['height'] >= 0 and c['value'] > 10000000)
        to_split_coin = None
        if len(confirmed_coins):
            confirmed_coins = sorted(confirmed_coins, key=lambda v: v['value'], reverse=True)
            to_split_coin = confirmed_coins[0]

        if to_split_coin is not None and len(all_coins) < coin_count:
            additional_count = coin_count - len(all_coins)
            unused_addresses = wallet.get_unused_addresses()
            if len(unused_addresses) < additional_count:
                wallet.create_new_addresses(False, additional_count)
                unused_addresses = wallet.get_unused_addresses()

            dispersal_value = to_split_coin['value'] - 2000
            outputs = []
            for i in range(additional_count):
                outputs.append((TYPE_ADDRESS, unused_addresses[i],
                    dispersal_value // additional_count))
            if sum(v[2] for v in outputs) > dispersal_value - (2 * len(outputs)):
                tx = wallet.make_unsigned_transaction([ to_split_coin ], outputs, app_state.config)
                wallet.sign_transaction(tx, password)
                return {
                    "tx_hex": str(tx),
                    "tx_id": tx.txid(),
                }

        return None

    def make_signed_opreturn_transaction(self, wallet_name: Optional[str]=None,
            password: Optional[str]=None, pushdatas_b64: Optional[List[str]]=None) -> dict:
        wallet = self._get_wallet(wallet_name)

        pushdatas = []
        for pushdata_b64 in pushdatas_b64:
            pushdata_bytes = base64.b64decode(pushdata_b64)
            pushdatas.append(pushdata_bytes)

        domain = None
        confirmed_coins = wallet.get_spendable_coins(None, {'confirmed_only': True})
        outputs = [ (TYPE_SCRIPT, ScriptOutput.as_op_return(pushdatas), 0) ]
        tx = wallet.make_unsigned_transaction(confirmed_coins, outputs, app_state.config)
        wallet.sign_transaction(tx, password)
        return {
            "tx_id": tx.txid(),
            "tx_hex": str(tx),
            "fee": tx.get_fee(),
        }

    def broadcast_transaction(self, tx_hex: Optional[str]=None, wallet_name: Optional[str]=None,
                              wallet_memo: Optional[str]=None) -> str:
        wallet = None
        if wallet_name and wallet_memo:
            wallet = self._get_wallet(wallet_name)

        tx = Transaction(tx_hex)
        try:
            tx_id = app_state.daemon.network.broadcast_transaction_and_wait(tx)
        except aiorpcx.jsonrpc.RPCError as e:
            if e.code == 1 and e.message.find("too-long-mempool-chain") != -1:
                return jsonrpclib.Fault(100, "too-long-mempool-chain")
            print("raising rpc error", e.code, e.message)
            raise e
        if tx.is_complete() and wallet_name and wallet_memo:
            wallet.set_label(tx_id, wallet_memo)
        return tx_id

    def get_transaction_state(self, tx_id: Optional[str]=None,
            wallet_name: Optional[str]=None) -> bool:
        wallet = self._get_wallet(wallet_name)
        if not wallet.has_received_transaction(tx_id):
            return None
        height, conf, timestamp = wallet.get_tx_height(tx_id)
        return height, conf, timestamp
