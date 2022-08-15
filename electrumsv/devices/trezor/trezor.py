from typing import cast, Optional, TYPE_CHECKING, Union

from bitcoinx import Address, bip32_key_from_string, be_bytes_to_int, \
    bip32_decompose_chain_string, BIP32PublicKey

from ...app_state import app_state
from ...constants import DerivationPath, unpack_derivation_path
from ...device import Device, DeviceInfo
from ...exceptions import UserCancelled
from ...i18n import _
from ...keystore import Hardware_KeyStore
from ...logs import logs
from ...networks import Net
from ...transaction import classify_transaction_output_script, HardwareSigningMetadata, \
    Transaction, TransactionContext, XTxInput, XTxOutput
from ...wallet import MultisigAccount, StandardAccount
from ...wallet_database.types import KeyListRow

from ...gui.qt.util import window_query_choice

from ..hw_wallet.plugin import HW_PluginBase, LibraryFoundButUnusable

if TYPE_CHECKING:
    from ...gui.qt.account_wizard import AccountWizard
    from ...gui.qt.util import WindowProtocol
    from ..hw_wallet.qt import QtHandlerBase
    from .qt import QtHandler, QtPlugin


logger = logs.get_logger("plugin.trezor")

try:
    import trezorlib
    import trezorlib.transport

    from .client import TrezorClientSV

    from trezorlib.client import PASSPHRASE_ON_DEVICE # pylint: disable=unused-import
    from trezorlib.messages import (
        RecoveryDeviceType, HDNodeType, HDNodePathType,
        InputScriptType, OutputScriptType, MultisigRedeemScriptType,
        TxInputType, TxOutputBinType, TxOutputType, TransactionType, SignTx)

    RECOVERY_TYPE_SCRAMBLED_WORDS = RecoveryDeviceType.ScrambledWords
    RECOVERY_TYPE_MATRIX = RecoveryDeviceType.Matrix

    TREZORLIB = True
except Exception as e:
    logger.warning(f"Failed to import trezorlib: {e}")
    TREZORLIB = False

    RECOVERY_TYPE_SCRAMBLED_WORDS, RECOVERY_TYPE_MATRIX, PASSPHRASE_ON_DEVICE = range(3)


# Trezor initialization methods
TIM_NEW, TIM_RECOVER = range(2)

TREZOR_PRODUCT_KEY = 'Trezor'

ValidWalletTypes = Union[StandardAccount, MultisigAccount]


class TrezorKeyStore(Hardware_KeyStore):
    hw_type = 'trezor'
    device = 'TREZOR'

    def get_derivation(self) -> str:
        return self.derivation

    def get_client(self, force_pair: bool=True) -> Optional["TrezorClientSV"]:
        return cast(TrezorPlugin, self.plugin).get_client(self, force_pair)

    def decrypt_message(self, sequence: DerivationPath, message: bytes, password: str) -> bytes:
        raise RuntimeError(_('Encryption and decryption are not implemented by {}').format(
            self.device))

    def sign_message(self, sequence: DerivationPath, message: bytes, password: str) -> bytes:
        client = self.get_client()
        assert client is not None
        address_path = self.get_derivation() + "/%d/%d"%sequence
        msg_sig = client.sign_message(address_path, message)
        return cast(bytes, msg_sig.signature)

    def requires_input_transactions(self) -> bool:
        return True

    def sign_transaction(self, tx: Transaction, password: str,
            context: TransactionContext) -> None:
        if tx.is_complete():
            return

        assert len(context.parent_transactions), "This keystore requires all input transactions"
        # path of the xpubs that are involved
        xpub_path: dict[str, str] = {}
        for txin in tx.inputs:
            for x_pubkey in txin.x_pubkeys.values():
                if not x_pubkey.is_bip32_key():
                    continue
                xpub = x_pubkey.bip32_extended_key()
                if xpub == self.get_master_public_key():
                    xpub_path[xpub] = self.get_derivation()

        assert self.plugin is not None
        cast(TrezorPlugin, self.plugin).sign_transaction(self, tx, xpub_path,
            context.hardware_signing_metadata, context.parent_transactions)


class TrezorPlugin(HW_PluginBase):
    firmware_URL = 'https://wallet.trezor.io'
    libraries_URL = 'https://pypi.org/project/trezor/'
    minimum_firmware = (1, 5, 2)
    keystore_class = TrezorKeyStore
    minimum_library = (0, 12, 0)
    maximum_library = (0, 13)
    DEVICE_IDS = [ TREZOR_PRODUCT_KEY ]

    MAX_LABEL_LEN = 32

    def __init__(self, name: str) -> None:
        super().__init__(name)
        self.logger = logger

        self.libraries_available = self.check_libraries_available()
        if not self.libraries_available:
            return

    def get_library_version(self) -> str:
        import trezorlib
        version: str
        try:
            version = trezorlib.__version__
        except Exception:
            version = 'unknown'
        if TREZORLIB:
            return version
        else:
            raise LibraryFoundButUnusable(library_version=version)

    def enumerate_devices(self) -> list[Device]:
        if not TREZORLIB:
            return []
        devices = trezorlib.transport.enumerate_devices()
        return [Device(path=d.get_path(),
                       interface_number=-1,
                       id_=d.get_path(),
                       product_key=TREZOR_PRODUCT_KEY,
                       usage_page=0,
                       transport_ui_string=d.get_path())
                for d in devices]

    def create_client(self, device: Device, handler: "QtHandlerBase") -> Optional["TrezorClientSV"]:
        try:
            logger.debug("connecting to device at %s", device.path)
            transport = trezorlib.transport.get_transport(device.path)
        except Exception as e:
            logger.error("cannot connect at %s %s", device.path, e)
            return None

        if not transport:
            logger.error("cannot connect at %s", device.path)
            return None

        logger.debug("connected to device at %s", device.path)
        # note that this call can still raise!
        return TrezorClientSV(transport, handler, self)

    def get_client(self, keystore: Hardware_KeyStore, force_pair: bool=True) \
            -> Optional["TrezorClientSV"]:
        client = cast(Optional[TrezorClientSV],
            app_state.device_manager.client_for_keystore(self, keystore, force_pair))
        # returns the client for a given keystore. can use xpub
        if client:
            client.used()
        return client

    def get_coin_name(self) -> str:
        return cast(str, Net.TREZOR_COIN_NAME)

    def initialize_device(self, device_id: str, wizard: "AccountWizard", handler: "QtHandler") \
            -> None:
        # Initialization method
        msg = _("Choose how you want to initialize your {}.\n\n"
                "The first two methods are secure as no secret information "
                "is entered into your computer."
        ).format(self.device, self.device)
        choices = [
            # Must be short as QT doesn't word-wrap radio button text
            _("Let the device generate a completely new seed randomly"),
            _("Recover from a seed you have previously written down"),
        ]
        methods = [ TIM_NEW, TIM_RECOVER ]
        client = cast(Optional[TrezorClientSV], app_state.device_manager.client_by_id(device_id))
        assert client is not None
        model = client.get_trezor_model()
        choice_index = window_query_choice(wizard, _('Initialize Device'), msg, choices)
        if choice_index is not None:
            method = methods[choice_index]

            import threading
            settings = cast("QtPlugin", self).request_trezor_init_settings(wizard, method,
                model)
            t = threading.Thread(target=self._initialize_device_safe,
                args=(settings, method, device_id, wizard, handler))
            t.setDaemon(True)
            t.start()

            # TODO(technical-debt) Broken account wizard. Old hardware wallet overlay code.
            1/0 # pylint: disable=pointless-statement
            # exit_code = wizard.loop.exec()
            # if exit_code != 0:
            #     # this method (initialize_device) was called with the expectation
            #     # of leaving the device in an initialized state when finishing.
            #     # signal that this is not the case:
            #     raise UserCancelled()

    def _initialize_device_safe(self, settings: tuple[int, str, bool, bool, int|None],
            method: int, device_id: str, wizard: "AccountWizard",
            handler: "QtHandler") -> None:
        exit_code = 0
        try:
            self._initialize_device(settings, method, device_id, wizard, handler)
        except UserCancelled:
            exit_code = 1
        except Exception as e:
            self.logger.exception("")
            handler.show_error(str(e))
            exit_code = 1
        finally:
            # TODO(technical-debt) Broken account wizard. Old hardware wallet overlay code.
            pass
            # wizard.loop.exit(exit_code)

    def _initialize_device(self, settings: tuple[int, str, bool, bool, int|None],
            method: int, device_id: str, wizard: "AccountWizard", handler: "QtHandler") -> None:
        item, label, pin_protection, passphrase_protection, recovery_type = settings

        if method == TIM_RECOVER and recovery_type == RECOVERY_TYPE_SCRAMBLED_WORDS:
            handler.show_error(_(
                "You will be asked to enter 24 words regardless of your "
                "seed's actual length.  If you enter a word incorrectly or "
                "misspell it, you cannot change it or go back - you will need "
                "to start again from the beginning.\n\nSo please enter "
                "the words carefully!"),
                blocking=True)

        client = cast(TrezorClientSV, app_state.device_manager.client_by_id(device_id))

        if method == TIM_NEW:
            client.reset_device(
                strength=64 * (item + 2),  # 128, 192 or 256
                passphrase_protection=passphrase_protection,
                pin_protection=pin_protection,
                label=label)
        elif method == TIM_RECOVER:
            assert isinstance(recovery_type, int)
            client.recover_device(
                recovery_type=recovery_type,
                word_count=6 * (item + 2),  # 12, 18 or 24
                passphrase_protection=passphrase_protection,
                pin_protection=pin_protection,
                label=label)
            if recovery_type == RECOVERY_TYPE_MATRIX:
                handler.close_matrix_dialog()
        else:
            raise RuntimeError("Unsupported recovery method")

    def _make_node_path(self, xpub: str, address_n: DerivationPath) -> "HDNodePathType":
        pubkey = bip32_key_from_string(xpub)
        derivation = pubkey.derivation()
        node = HDNodeType(
            depth=derivation.depth,
            fingerprint=be_bytes_to_int(pubkey.fingerprint()),
            child_num=derivation.n,
            chain_code=derivation.chain_code,
            public_key=pubkey.to_bytes(),
        )
        return HDNodePathType(node=node, address_n=list(address_n))

    def setup_device(self, device_info: DeviceInfo, wizard: "AccountWizard") -> None:
        '''Called when creating a new wallet.  Select the device to use.  If
        the device is uninitialized, go through the intialization
        process.'''
        device_id = device_info.device.id_
        client = cast(Optional[TrezorClientSV], app_state.device_manager.client_by_id(device_id))
        if client is None:
            raise Exception(_('Failed to create a client for this device.') + '\n' +
                            _('Make sure it is in the correct state.'))
        window = cast("WindowProtocol", wizard)
        client.handler = cast("QtHandler", self.create_handler(window))
        if not device_info.initialized:
            self.initialize_device(device_id, wizard, client.handler)
        client.get_master_public_key('m', creating=True)

    def get_master_public_key(self, device_id: str, derivation: str, wizard: "AccountWizard") \
            -> BIP32PublicKey:
        client = cast(Optional[TrezorClientSV], app_state.device_manager.client_by_id(device_id))
        assert client is not None
        window = cast("WindowProtocol", wizard)
        client.handler = cast("QtHandler", self.create_handler(window))
        return client.get_master_public_key(derivation)

    def get_trezor_input_script_type(self, is_multisig: bool) -> int:
        if is_multisig:
            return cast(int, InputScriptType.SPENDMULTISIG)
        else:
            return cast(int, InputScriptType.SPENDADDRESS)

    def sign_transaction(self, keystore: TrezorKeyStore, tx: Transaction,
            xpub_path: dict[str, str], signing_metadata: list[HardwareSigningMetadata],
            previous_transactions: dict[bytes, Transaction]) -> None:
        prev_txtypes: dict[bytes, TransactionType] = {}
        for prev_tx_hash, prev_tx in previous_transactions.items():
            txtype = TransactionType()
            txtype.version = prev_tx.version
            txtype.lock_time = prev_tx.locktime
            txtype.inputs = self.tx_inputs(prev_tx, is_prev_tx=True)
            txtype.bin_outputs = [
                TxOutputBinType(amount=tx_output.value,
                    script_pubkey=bytes(tx_output.script_pubkey)) for tx_output in prev_tx.outputs
            ]
            # Trezor tx hashes are same byte order as the reversed hex tx id.
            prev_trezor_tx_hash = bytes(reversed(prev_tx_hash))
            prev_txtypes[prev_trezor_tx_hash] = txtype

        client = self.get_client(keystore)
        assert client is not None
        inputs = self.tx_inputs(tx, xpub_path)
        outputs = self.tx_outputs(keystore, keystore.get_derivation(), tx, signing_metadata)
        details = SignTx(lock_time=tx.locktime)
        signatures, _ = client.sign_tx(self.get_coin_name(), inputs, outputs, details=details,
            prev_txes=prev_txtypes)
        tx.update_signatures(signatures)

    def show_key(self, account: ValidWalletTypes, keydata: KeyListRow) -> None:
        keystore = cast(TrezorKeyStore, account.get_keystore())
        client = self.get_client(keystore)
        assert client is not None
        assert keydata.derivation_data2 is not None
        derivation_path = unpack_derivation_path(keydata.derivation_data2)
        assert derivation_path is not None
        subpath = '/'.join(str(x) for x in derivation_path)
        derivation_text = f"{keystore.derivation}/{subpath}"

        # prepare multisig, if available:
        xpubs = account.get_master_public_keys()
        if len(xpubs) > 1:
            account = cast(MultisigAccount, account)
            pubkeys = [pubkey.to_hex() for pubkey in
                account.get_public_keys_for_derivation(keydata.derivation_type,
                    keydata.derivation_data2)]
            # sort xpubs using the order of pubkeys
            sorted_pairs = sorted(zip(pubkeys, xpubs))
            multisig = self._make_multisig(
                account.m,
                [(xpub, derivation_path) for _, xpub in sorted_pairs])
        else:
            multisig = None

        script_type = self.get_trezor_input_script_type(multisig is not None)
        client.show_address(derivation_text, script_type, multisig)

    def tx_inputs(self, tx: Transaction, xpub_path: dict[str, str]|None=None,
            is_prev_tx: bool=False) -> list["TxInputType"]:
        inputs = []
        txin: XTxInput
        for txin in tx.inputs:
            txinputtype = TxInputType()
            # Trezor tx hashes are same byte order as the reversed hex tx id.
            txinputtype.prev_hash = bytes(reversed(txin.prev_hash))
            txinputtype.prev_index = txin.prev_idx
            txinputtype.sequence = txin.sequence
            txinputtype.amount = txin.value
            if txin.script_sig:
                txinputtype.script_sig = bytes(txin.script_sig)
            if not is_prev_tx:
                assert xpub_path is not None, "no xpubs provided for hw signing operation"
                xpubs: list[tuple[str, DerivationPath]] = []
                signatures: list[bytes] = []
                for public_key_bytes, x_pubkey in txin.x_pubkeys.items():
                    xpubs.append(x_pubkey.bip32_extended_key_and_path())
                    signatures.append(txin.signatures[public_key_bytes][:-1] if public_key_bytes
                        in txin.signatures else b'')
                multisig = self._make_multisig(txin.threshold, xpubs,
                    signatures)
                if multisig is not None:
                    txinputtype.multisig = multisig
                txinputtype.script_type = self.get_trezor_input_script_type(multisig is not None)
                # find which key is mine
                for xpub, path in xpubs:
                    if xpub in xpub_path:
                        xpub_n = tuple(bip32_decompose_chain_string(xpub_path[xpub]))
                        # Sequences cannot be added according to mypy, annoying..
                        txinputtype.address_n = list(xpub_n + path)
                        break
            inputs.append(txinputtype)

        return inputs

    def _make_multisig(self, m: int, xpubs: list[tuple[str, DerivationPath]],
            signatures: list[bytes]|None=None) -> Optional["MultisigRedeemScriptType"]:
        if len(xpubs) == 1:
            return None

        pubkeys = [self._make_node_path(xpub, deriv) for xpub, deriv in xpubs]
        if signatures is None:
            signatures = [b''] * len(pubkeys)
        elif len(signatures) != len(pubkeys):
            raise RuntimeError('Mismatched number of signatures')

        return MultisigRedeemScriptType(
            pubkeys=pubkeys,
            signatures=signatures,
            m=m)

    def tx_outputs(self, keystore: TrezorKeyStore, derivation: str, tx: Transaction,
            signing_metadata: list[HardwareSigningMetadata]) -> list["TxOutputType"]:
        account_derivation: DerivationPath = tuple(bip32_decompose_chain_string(derivation))
        keystore_fingerprint = keystore.get_fingerprint()

        def create_output_by_derivation(key_derivation: DerivationPath, xpubs: tuple[str],
                m: int) -> TxOutputType:
            multisig = self._make_multisig(m, [(xpub, key_derivation) for xpub in xpubs])
            if multisig is None:
                script_type = OutputScriptType.PAYTOADDRESS
            else:
                script_type = OutputScriptType.PAYTOMULTISIG
            return TxOutputType(
                multisig=multisig,
                amount=tx_output.value,
                address_n=[ *account_derivation, *key_derivation ],
                script_type=script_type
            )

        def create_output_by_address(tx_output: XTxOutput) -> TxOutputType:
            txoutputtype = TxOutputType()
            txoutputtype.amount = tx_output.value
            _esv_script_type, _threshold, address = classify_transaction_output_script(
                tx_output.script_pubkey)
            if isinstance(address, Address):
                txoutputtype.script_type = OutputScriptType.PAYTOADDRESS
                txoutputtype.address = address.to_string()
            return txoutputtype

        outputs = []
        for i, tx_output in enumerate(tx.outputs):
            if len(signing_metadata) and keystore_fingerprint in signing_metadata[i]:
                output_info = signing_metadata[i][keystore_fingerprint]
                txoutputtype = create_output_by_derivation(*output_info)
            else:
                txoutputtype = create_output_by_address(tx_output)
            outputs.append(txoutputtype)
        return outputs
