import concurrent
import json
import logging
import time
from typing import Any, Callable, Iterable, List, Optional

import bitcoinx
from aiorpcx import run_in_thread
from bitcoinx import hash_to_hex_str

from electrumsv.app_state import app_state
from electrumsv.transaction import Transaction
from electrumsv.wallet import AbstractAccount, UTXO

from .constants import WalletEventNames
from .errors import Errors
from .handlers import ExtensionEndpoints


class RESTAPIApplication:

    def __init__(self):
        self.logger = logging.getLogger("wallet-app")
        self.app_state = app_state  # easier to mock

    def run_app(self):
        self.logger.debug("entering application main loop")
        try:
            while app_state.async_.loop.is_running():
                time.sleep(0.1)  # sole purpose is timely cleanup on KeyboardInterrupt
        finally:
            self._teardown_app()
            self.logger.debug("exited application main loop")

    def run_coro(self, coro, *args, on_done=None):
        future = app_state.async_.spawn(coro, *args, on_done=on_done)
        return future

    def run_in_thread(self, func, *args,
            on_done: Optional[Callable[[concurrent.futures.Future], None]]=None):
        return self.run_coro(run_in_thread, func, *args, on_done=on_done)

    def setup_app(self) -> None:
        # app_state.daemon is initialised after app. Setup things dependent on daemon here.
        self.logger.debug("setting up daemon-app")
        self.restapi = ExtensionEndpoints()

        # state management of the websocket must be via the aiohttp.web.Application object
        # access from TxStateWebSocket View via self.request.app['ws_clients'] and
        self.aiohttp_web_app = self.app_state.daemon.rest_server.app
        self.aiohttp_web_app['ws_clients'] = {}  # uuid: WSClient
        self.aiohttp_web_app['tx_registrations_map'] = {}  # uuid: set of tx_hashes
        self.aiohttp_web_app['restapi'] = self.restapi
        self.app_state.daemon.rest_server.register_routes(self.restapi)

    def _teardown_app(self) -> None:
        for client in self.aiohttp_web_app['ws_clients'].values():
            app_state.async_.spawn(client.websocket.close())

    def get_and_set_frozen_utxos_for_tx(self, tx: Transaction, child_wallet: AbstractAccount,
                                        freeze: bool=True) -> List[UTXO]:
        spendable_coins = child_wallet.get_utxos(exclude_frozen=False)
        input_keys = set(
            [(bitcoinx.hash_to_hex_str(input.prev_hash), input.prev_idx) for input in tx.inputs])
        frozen_utxos = [utxo for utxo in spendable_coins if utxo.key() in input_keys]
        child_wallet.set_frozen_coin_state(frozen_utxos, freeze)
        return frozen_utxos

    def on_new_wallet_event(self, wallet_path, row) -> None:
        # an expected api when resetting / creating a new wallet...
        pass

    def on_triggered_event(self, *event_data: Iterable[Any]):
        self.app_state.async_.spawn(self.async_on_triggered_event(*event_data))

    async def async_on_triggered_event(self, *event_data: Any) -> None:
        event_name = event_data[0]
        if event_name == WalletEventNames.TRANSACTION_STATE_CHANGE:
            _event_name, _acc_id, tx_hash, existing_flags, updated_flags = event_data
            await self._tx_state_push_notification(tx_hash)
        elif event_name == WalletEventNames.TRANSACTION_ADDED:
            _event_name, tx_hash, _tx, _involved_account_ids, _external = event_data
            await self._tx_state_push_notification(tx_hash)
        elif event_name == WalletEventNames.VERIFIED:
            _event_name, tx_hash, height, conf, timestamp = event_data
            await self._tx_state_push_notification(tx_hash)

    async def _tx_state_push_notification(self, tx_hash):
        """send push notification to all relevant websockets for the tx_hash"""
        websocket_ids = self.aiohttp_web_app['tx_registrations_map'].keys()
        for ws_id in websocket_ids:
            # only notify relevant websockets
            if tx_hash in self.aiohttp_web_app['tx_registrations_map'][ws_id]:
                client = self.aiohttp_web_app['ws_clients'][ws_id]
                tx_flags = client.account._wallet._transaction_cache.get_flags(tx_hash)
                if not tx_flags:
                    response_json = json.dumps({
                        "code": Errors.GENERIC_BAD_REQUEST_CODE,
                        "message": f"this txid: {hash_to_hex_str(tx_hash)} does not belong to "
                                   f"this account_id: {client.account._id}"
                    })
                    self.logger.debug(f"push notification to websocket={ws_id}: {response_json}")
                    await client.websocket.send_str(response_json)
                    continue
                response_json = json.dumps({
                    "txid": hash_to_hex_str(tx_hash),
                    "tx_flags": int(tx_flags)
                })
                self.logger.debug(f"push notification to websocket {ws_id}: {response_json}")
                await client.websocket.send_str(response_json)
