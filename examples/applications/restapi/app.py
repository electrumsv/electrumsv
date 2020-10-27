import concurrent
import logging
import time
from typing import List, Optional, Callable

import bitcoinx
from aiorpcx import run_in_thread

from electrumsv.app_state import app_state
from electrumsv.transaction import Transaction
from electrumsv.wallet import UTXO, AbstractAccount
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
        self.app_state.daemon.rest_server.register_routes(self.restapi)

    def _teardown_app(self) -> None:
        pass

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
