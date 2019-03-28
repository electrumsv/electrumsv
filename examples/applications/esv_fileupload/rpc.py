import base64
import enum
import os
from typing import Optional, Tuple

from electrumsv.app_state import app_state
from electrumsv.address import ScriptOutput
from electrumsv.bitcoin import TYPE_SCRIPT
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

    def _make_signed_transaction(self, wallet, password, outputs):
        domain = None
        coins = wallet.get_spendable_coins(domain, app_state.config)
        tx = wallet.make_unsigned_transaction(coins, outputs, app_state.config)
        wallet.sign_transaction(tx, password)
        return tx

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

    def create_file_transactions(self, b64message: Optional[str]=None,
            wallet_name: Optional[str]=None, password: Optional[str]=None,
            protocol: Optional[int]=FileProtocol.B, media_type: Optional[str]=None,
            encoding: Optional[str]=None, file_name: Optional[str]=None) -> str:
        wallet = self._get_wallet(wallet_name)

        try:
            FileProtocol(protocol)
        except ValueError:
            raise RPCError("Unknown protocol")

        message_bytes = base64.b64decode(b64message)

        if len(message_bytes) > 99000:
            if protocol == FileProtocol.B:
                raise RPCError("message too large for B protocol")
        else:
            if protocol == FileProtocol.Bcat:
                raise RPCError("message too small for Bcat protocol")

        transactions = []

        if protocol == FileProtocol.B:
            push_values = [
                b"19HxigV4QyBv3tHpQVcUEQyq1pzZVdoAut",
                message_bytes,
                bytes(media_type, "utf-8"),
            ]
            if encoding:
                push_values.append(bytes(encoding, "utf-8"))
            if file_name:
                if not encoding:
                    raise RPCError("must provide encoding with filename")
                push_values.append(bytes(file_name, "utf-8"))
            outputs = [ (TYPE_SCRIPT, ScriptOutput.as_op_return(push_values), 0) ]
            tx = self._make_signed_transaction(wallet, password, outputs)
            transactions.append(tx)
        elif protocol == FileProtocol.Bcat:
            index = 0
            message_view = memoryview(message_bytes)
            while index < len(message_view):
                segment_bytes = bytes(message_view[index:index+99000])

                push_values = [
                    b"1ChDHzdd1H4wSjgGMHyndZm6qxEDGjqpJL",
                    segment_bytes
                ]
                outputs = [ (TYPE_SCRIPT, ScriptOutput.as_op_return(push_values), 0) ]
                tx = self._make_signed_transaction(wallet, password, outputs)
                transactions.append(tx)

                index += 99000

            push_values = [
                b"15DHFxWZJT58f9nhyGnsRBqrgwK4W6h4Up",
                b"ElectrumSV",
                bytes(media_type, "utf-8"),
                bytes(encoding, "utf-8") if encoding is not None else b"",
                bytes(file_name, "utf-8") if file_name is not None else b"",
                b"",
            ]
            for message_tx in transactions:
                message_tx_hex = message_tx.serialize()
                tx_bytes = bytes.fromhex(message_tx_hex)
                txid_bytes = sha256d(tx_bytes)
                push_values.append(txid_bytes)

            outputs = [ (TYPE_SCRIPT, ScriptOutput.as_op_return(push_values), 0) ]
            tx = self._make_signed_transaction(wallet, password, outputs)
            transactions.append(tx)

        results = []
        for tx in transactions:
            results.append({
                "tx_id": tx.txid(),
                "tx_hex": str(tx),
                "fee": tx.get_fee(),
            })
        return results

    def broadcast_transaction(self, tx_hex: Optional[str]=None, wallet_name: Optional[str]=None,
                              wallet_memo: Optional[str]=None) -> str:
        wallet = None
        if wallet_name and wallet_memo:
            wallet = self._get_wallet(wallet_name)

        tx = Transaction(tx_hex)
        tx_id = app_state.daemon.network.broadcast_transaction_and_wait(tx)
        if tx.is_complete() and wallet_name and wallet_memo:
            wallet.set_label(tx_id, wallet_memo)
        return tx_id

