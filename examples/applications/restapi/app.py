import logging
import time
from typing import List

import bitcoinx

from electrumsv.app_state import app_state
from electrumsv.transaction import Transaction
from electrumsv.wallet import UTXO, Abstract_Wallet
from .handlers import ExtensionEndpoints


class RESTAPIApplication:

    def __init__(self):
        self.logger = logging.getLogger("wallet-app")

    def run_app(self):
        self.logger.debug("entering application main loop")
        try:
            while app_state.async_.loop.is_running():
                time.sleep(0.1)  # sole purpose is timely cleanup on KeyboardInterrupt
        finally:
            self._teardown_app()
            self.logger.debug("exited application main loop")

    def setup_app(self) -> None:
        # app_state.daemon is initialised after app. Setup things dependent on daemon here.
        self.logger.debug("setting up daemon-app")
        app_state.daemon.rest_server.register_routes(ExtensionEndpoints())

    def _teardown_app(self) -> None:
        pass

    def get_and_set_frozen_utxos_for_tx(self, tx: Transaction, child_wallet: Abstract_Wallet,
                                        freeze: bool=True) -> List[UTXO]:
        spendable_coins = child_wallet.get_utxos(exclude_frozen=False)
        input_keys = set(
            [(bitcoinx.hash_to_hex_str(input.prev_hash), input.prev_idx) for input in tx.inputs])
        frozen_utxos = [utxo for utxo in spendable_coins if utxo.key() in input_keys]
        child_wallet.set_frozen_coin_state(frozen_utxos, freeze)
        return frozen_utxos