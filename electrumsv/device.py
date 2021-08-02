# ElectrumSV - lightweight Bitcoin client
# Copyright (C) 2015 Thomas Voegtlin
# Copyright (C) 2019-2020 The ElectrumSV Developers
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

from abc import ABC
import threading
import time
from typing import Any, cast, Dict, List, NamedTuple, Optional, Tuple, TYPE_CHECKING, \
    TypedDict, Union

from bitcoinx import BIP32PublicKey

from .app_state import app_state
from .i18n import _
from .exceptions import UserCancelled
from .logs import logs

if TYPE_CHECKING:
    from .devices.hw_wallet.plugin import HW_PluginBase
    from .devices.hw_wallet.qt import QtHandlerBase
    from .keystore import Hardware_KeyStore
    from .types import MasterKeyDataHardware
    from .wallet_database.types import MasterKeyRow


logger = logs.get_logger("devices")


class Device(NamedTuple):
    # TODO(hid-path-debacle) If you call `hid.enumerate` this is `bytes`, but if you look at
    #   dependent library code they expect it to be a string.. The existing code seems to treat it
    #   that way too, so not sure what to do about `path`.
    path: str
    interface_number: int
    id_: str
    product_key: Any
    usage_page: int
    transport_ui_string: str


class DeviceInfo(NamedTuple):
    device: Device
    label: str
    initialized: bool


class HidEntry(TypedDict):
    # TODO(hid-path-debacle) Is actually `bytes` but existing code expects `str` when it uses it.
    path: str # bytes
    vendor_id: int
    product_id: int
    serial_number: str
    release_number: int
    manufacturer_string: str
    product_string: str
    usage_page: int
    usage: int
    interface_number: int


class DeviceError(Exception):
    pass


class DeviceUnpairableError(DeviceError):
    pass


class SVBaseClient(ABC):
    handler: "QtHandlerBase"

    def close(self) -> None:
        raise NotImplementedError

    def timeout(self, cutoff: float) -> None:
        raise NotImplementedError

    def label(self) -> str:
        raise NotImplementedError

    def has_usable_connection_with_device(self) -> bool:
        raise NotImplementedError

    def get_master_public_key(self, bip32_path: str) -> Optional[BIP32PublicKey]:
        raise NotImplementedError

    def is_pairable(self) -> bool:
        raise NotImplementedError

    def is_initialized(self) -> bool:
        raise NotImplementedError


class DeviceMgr:
    '''Manages hardware clients.  A client communicates over a hardware channel with the
    device.

    In addition to tracking device HID IDs, the device manager tracks hardware wallets and
    manages wallet pairing.  A HID ID may be paired with a wallet when it is confirmed
    that the hardware device matches the wallet, i.e. they have the same master public
    key.  A HID ID can be unpaired if e.g. it is wiped.

    Because of hotplugging, a wallet must request its client dynamically each time it is
    required, rather than caching it itself.

    The device manager is global, so just one place does hardware scans when needed.  By
    tracking HID IDs, if a device is plugged into a different port the wallet is
    automatically re-paired.

    Wallets are informed on connect / disconnect events.  It must implement connected(),
    disconnected() callbacks.  Being connected implies a pairing.  Callbacks can happen in
    any thread context, and we do them without holding the lock.

    Confusingly, the HID ID (serial number) reported by the HID system doesn't match the
    device ID reported by the device itself.  We use the HID IDs.
    '''
    all_devices = ['digitalbitbox', 'keepkey', 'ledger', 'trezor']

    def __init__(self) -> None:
        self.plugins: Dict[str, "HW_PluginBase"] = {}
        # Keyed by xpub.  The value is the device id
        # has been paired, and None otherwise.
        self.xpub_ids: Dict[str, str] = {}
        # A list of clients.  The key is the client, the value is
        # a (path, id_) pair.
        self.clients: Dict[SVBaseClient, Tuple[str, str]] = {}
        # For synchronization
        self.lock = threading.RLock()
        self.hid_lock = threading.RLock()

    # NOTE(typing) Mapping these module types into some kind of union would be painful.
    @classmethod
    def _module(cls, device_kind: str): # type: ignore
        if device_kind == 'trezor':
            import electrumsv.devices.trezor as module1
            return module1
        elif device_kind == 'keepkey':
            import electrumsv.devices.keepkey as module2
            return module2
        elif device_kind == 'ledger':
            import electrumsv.devices.ledger as module3
            return module3
        elif device_kind == 'digitalbitbox':
            import electrumsv.devices.digitalbitbox as module4
            return module4
        else:
            raise DeviceError(f'unsupported device kind: {device_kind}')

    @classmethod
    def _plugin_class(cls, device_kind: str) -> "HW_PluginBase":
        return cast("HW_PluginBase", cls._module(device_kind).plugin_class(app_state.gui_kind))

    def _create_client(self, device: Device, handler: "QtHandlerBase", plugin: "HW_PluginBase") \
            -> Optional[SVBaseClient]:
        # Get from cache first
        client = self.client_lookup(device.id_)
        if client:
            return client
        client = plugin.create_client(device, handler)
        if client:
            logger.debug("Registering %s", client)
            with self.lock:
                self.clients[client] = (device.path, device.id_)
        return client

    def _client_by_xpub(self, plugin: "HW_PluginBase", xpub: str, handler: "QtHandlerBase",
            devices: List[Device]) -> Optional[SVBaseClient]:
        client: Optional[SVBaseClient] = None
        _id = self.xpub_id(xpub)
        if _id is not None:
            client = self.client_lookup(_id)
        if client:
            # An unpaired client might have another wallet's handler
            # from a prior scan.  Replace to fix dialog parenting.
            client.handler = handler
            return client

        for device in devices:
            if device.id_ == _id:
                return self._create_client(device, handler, plugin)

        return None

    def _force_pair_xpub(self, plugin: "HW_PluginBase", handler: "QtHandlerBase", info: DeviceInfo,
            xpub: str, derivation: str, devices: List[Device]) -> SVBaseClient:
        # The wallet has not been previously paired, so let the user
        # choose an unpaired device and compare its first address.
        client = self.client_lookup(info.device.id_)
        if client and client.is_pairable():
            # See comment above for same code
            client.handler = handler
            # This will trigger a PIN/passphrase entry request
            try:
                client_mpk = client.get_master_public_key(derivation)
            except (UserCancelled, RuntimeError):
                # Bad / cancelled PIN / passphrase
                client_mpk = None
            if client_mpk is not None and client_mpk.to_extended_key_string() == xpub:
                self.pair_xpub(xpub, info.device.id_)
                return client

        # The user input has wrong PIN or passphrase, or cancelled input,
        # or it is not pairable
        raise DeviceUnpairableError(
            _('ElectrumSV cannot pair with your {}.\n\nBefore you request bitcoins to be '
              'sent to addresses in this wallet, ensure you can pair with your device, '
              'or that you have its seed (and passphrase, if any). Otherwise all '
              'bitcoins you receive will be unspendable.').format(plugin.device))

    def timeout_clients(self) -> None:
        '''Handle device timeouts.'''
        with self.lock:
            clients = list(self.clients.keys())
        cutoff = time.time() - app_state.config.get_session_timeout()
        for client in clients:
            client.timeout(cutoff)

    def get_plugin(self, device_kind: str) -> "HW_PluginBase":
        # There need only be one instance per device kind.
        if device_kind not in self.plugins:
            plugin_class = self._plugin_class(device_kind)
            # NOTE(typing) `HW_PluginBase` is not callable, but we are not dealing with that
            #   but rather one of the HW wallet subclasses that derive from it.
            plugin = plugin_class(device_kind) # type: ignore
            self.plugins[device_kind] = plugin
            logger.debug("loaded %s", device_kind)
        return self.plugins[device_kind]

    def create_keystore(self, data: "MasterKeyDataHardware", row: Optional['MasterKeyRow']) \
            -> 'Hardware_KeyStore':
        plugin = self.get_plugin(data['hw_type'])
        return plugin.create_keystore(data, row)

    def supported_devices(self) -> Dict[str, Union["HW_PluginBase", Exception]]:
        '''Returns a dictionary.  Keys are all supported device kinds; the value is
        the plugin object, or the exception if it could not be instantiated.'''
        def plugin(device_kind: str) -> Union["HW_PluginBase", Exception]:
            try:
                return self.get_plugin(device_kind)
            except Exception as e:
                return e

        return {device_kind: plugin(device_kind) for device_kind in self.all_devices}

    def xpub_id(self, xpub: str) -> Optional[str]:
        with self.lock:
            return self.xpub_ids.get(xpub)

    def xpub_by_id(self, id_: str) -> Optional[str]:
        with self.lock:
            for xpub, xpub_id in self.xpub_ids.items():
                if xpub_id == id_:
                    return xpub
            return None

    def unpair_xpub(self, xpub: str) -> None:
        with self.lock:
            if xpub not in self.xpub_ids:
                return
            _id = self.xpub_ids.pop(xpub)
            self._close_client(_id)

    def unpair_id(self, id_: str) -> None:
        xpub = self.xpub_by_id(id_)
        if xpub:
            self.unpair_xpub(xpub)
        else:
            self._close_client(id_)

    def _close_client(self, id_: str) -> None:
        client = self.client_lookup(id_)
        if client:
            self.clients.pop(client, None)
            client.close()

    def pair_xpub(self, xpub: str, id_: str) -> None:
        with self.lock:
            self.xpub_ids[xpub] = id_

    def client_lookup(self, id_: str) -> Optional[SVBaseClient]:
        with self.lock:
            for client, (path, client_id) in self.clients.items():
                if client_id == id_:
                    return client
        return None

    def client_by_id(self, id_: str) -> Optional[SVBaseClient]:
        '''Returns a client for the device ID if one is registered.  If a device is wiped or in
        bootloader mode pairing is impossible; in such cases we communicate by device ID
        and not wallet.
        '''
        self.scan_devices()
        return self.client_lookup(id_)

    def client_for_keystore(self, plugin: "HW_PluginBase", keystore: "Hardware_KeyStore",
            force_pair: bool) -> Optional[SVBaseClient]:
        logger.debug("getting client for keystore")
        assert keystore.plugin is not None
        if not keystore.plugin.libraries_available:
            raise RuntimeError(keystore.plugin_qt.missing_message())
        handler = keystore.handler_qt
        assert handler is not None
        handler.update_status(False)
        devices = self.scan_devices()
        xpub = keystore.xpub
        assert xpub is not None
        derivation = keystore.derivation
        client = self._client_by_xpub(plugin, xpub, handler, devices)
        if client is None and force_pair:
            info = self.select_device(plugin, handler, keystore, devices)
            client = self._force_pair_xpub(plugin, handler, info, xpub, derivation, devices)
        if client:
            handler.update_status(True)
        return client

    def unpaired_device_infos(self, handler: "QtHandlerBase", plugin: "HW_PluginBase",
            devices: Optional[List[Device]]=None) -> List[DeviceInfo]:
        '''Returns a list of DeviceInfo objects: one for each connected,
        unpaired device accepted by the hardware.'''
        if not plugin.libraries_available:
            raise RuntimeError(plugin.get_library_not_available_message())
        if devices is None:
            devices = self.scan_devices()
        devices = [dev for dev in devices if not self.xpub_by_id(dev.id_)]
        infos: List[DeviceInfo] = []
        for device in devices:
            if device.product_key not in plugin.DEVICE_IDS:
                continue
            try:
                client = self._create_client(device, handler, plugin)
            except Exception as e:
                logger.debug('failed to create client for %s at %s: %r',
                             plugin.name, device.path, e)
                continue
            if not client:
                continue
            infos.append(DeviceInfo(device, client.label(), client.is_initialized()))

        return infos

    def select_device(self, plugin: "HW_PluginBase", handler: "QtHandlerBase",
            keystore: "Hardware_KeyStore", devices: Optional[List[Device]]=None) -> DeviceInfo:
        '''Ask the user to select a device to use if there is more than one, and return the
        DeviceInfo for the device.
        '''
        while True:
            infos = self.unpaired_device_infos(handler, plugin, devices)
            if infos:
                break
            msg = _('Please insert your {}.  Verify the cable is connected and that no other '
                    'application is using it.\n\nTry to connect again?').format(plugin.device)
            if not handler.yes_no_question(msg):
                raise UserCancelled()
            devices = None
        if len(infos) == 1:
            return infos[0]
        # select device by label
        for info in infos:
            if info.label == keystore.label:
                return info
        msg = _("Please select which {} device to use:").format(plugin.device)
        descriptions = ['{} ({})'
                        .format(info.label, _("initialized") if info.initialized else _("wiped"))
                        for info in infos]
        c = handler.query_choice(msg, descriptions)
        assert c is not None, "UserCancelled should already be raised"
        info = infos[c]
        # save new label
        keystore.set_label(info.label)
        return info

    def find_hid_devices(self, device_ids: List[Tuple[int, int]]) -> List[Device]:
        # Devices with a list of product keys that have to be found by hid should call this
        # method.
        # device_ids -- List of known (vendor_id, product_id) pairs (a pair is a product key).
        try:
            import hid
        except ImportError:
            return []

        with self.hid_lock:
            hid_list = cast(List[HidEntry], hid.enumerate(0, 0))

        devices: List[Device] = []
        for d in hid_list:
            product_id = d['product_id']
            vendor_id = d['vendor_id']
            product_key = (vendor_id, product_id)
            if product_key not in device_ids:
                continue

            # Older versions of hid don't provide interface_number
            interface_number = d.get('interface_number', -1)
            path = d['path']
            serial_number = d['serial_number']
            usage_page = d['usage_page']

            if len(serial_number) == 0:
                serial_number = str(path)
            serial_number += str(interface_number) + str(usage_page)
            devices.append(Device(path=path,
                interface_number=interface_number,
                id_=serial_number,
                product_key=product_key,
                usage_page=usage_page,
                transport_ui_string='hid'))
        return devices

    def scan_devices(self) -> List[Device]:
        logger.debug("scanning devices...")

        # Let plugins enumerate devices
        devices: List[Device] = []
        for vendor, plugin in self.supported_devices().items():
            if not isinstance(plugin, Exception):
                try:
                    devices.extend(plugin.enumerate_devices())
                except Exception as e:
                    logger.exception(f"Failed to enumerate devices from {vendor} plugin")

        # find out what was disconnected
        pairs = [(dev.path, dev.id_) for dev in devices]
        disconnected_ids = []
        with self.lock:
            connected = {}
            for client, pair in self.clients.items():
                if pair in pairs and client.has_usable_connection_with_device():
                    connected[client] = pair
                else:
                    disconnected_ids.append(pair[1])
            self.clients = connected

        # Unpair disconnected devices
        for id_ in disconnected_ids:
            self.unpair_id(id_)

        return devices

