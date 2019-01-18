# ElectrumSV - lightweight Bitcoin client
# Copyright (C) 2015 Thomas Voegtlin
# Copyright (C) 2019 ElectrumSV developers
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

from collections import namedtuple
import threading
import time

from . import bip32
from .app_state import app_state
from .i18n import _
from .exceptions import UserCancelled
from .logs import logs
from .util import ThreadJob


logger = logs.get_logger("devices")
Device = namedtuple("Device", "path interface_number id_ product_key "
                    "usage_page transport_ui_string")
DeviceInfo = namedtuple("DeviceInfo", "device label initialized")
supported_devices = ['digitalbitbox', 'keepkey', 'ledger', 'trezor']


class DeviceError(Exception):
    pass


class DeviceUnpairableError(Exception):
    pass


def module(device_kind):
    if device_kind == 'trezor':
        import electrumsv.devices.trezor as mod
    elif device_kind == 'keepkey':
        import electrumsv.devices.keepkey as mod
    elif device_kind == 'ledger':
        import electrumsv.devices.ledger as mod
    elif device_kind == 'digitalbitbox':
        import electrumsv.devices.digitalbitbox as mod
    else:
        raise DeviceError(f'unsupported device kind: {device_kind}')
    return mod


def plugin_class(device_kind):
    '''Returns a class.'''
    return module(device_kind).plugin(app_state.gui_kind)


class DeviceMgr(ThreadJob):
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

    def __init__(self):
        super().__init__()
        # Keyed by xpub.  The value is the device id
        # has been paired, and None otherwise.
        self.xpub_ids = {}
        # A list of clients.  The key is the client, the value is
        # a (path, id_) pair.
        self.clients = {}
        # What we recognise.  Each entry is a (vendor_id, product_id) pair.
        self.recognised_hardware = set()
        # Custom enumerate functions for devices we don't know about.
        self.enumerate_func = set()
        # For synchronization
        self.lock = threading.RLock()
        self.hid_lock = threading.RLock()

    def thread_jobs(self):
        # Thread job to handle device timeouts
        return [self]

    def run(self):
        '''Handle device timeouts.'''
        with self.lock:
            clients = list(self.clients.keys())
        cutoff = time.time() - app_state.config.get_session_timeout()
        for client in clients:
            client.timeout(cutoff)

    def register_devices(self, device_pairs):
        for pair in device_pairs:
            self.recognised_hardware.add(pair)

    def register_enumerate_func(self, func):
        self.enumerate_func.add(func)

    def create_client(self, device, handler, hardware):
        # Get from cache first
        client = self.client_lookup(device.id_)
        if client:
            return client
        client = hardware.create_client(device, handler)
        if client:
            logger.debug("Registering %s", client)
            with self.lock:
                self.clients[client] = (device.path, device.id_)
        return client

    def xpub_id(self, xpub):
        with self.lock:
            return self.xpub_ids.get(xpub)

    def xpub_by_id(self, id_):
        with self.lock:
            for xpub, xpub_id in self.xpub_ids.items():
                if xpub_id == id_:
                    return xpub
            return None

    def unpair_xpub(self, xpub):
        with self.lock:
            if xpub not in self.xpub_ids:
                return
            _id = self.xpub_ids.pop(xpub)
            self._close_client(_id)

    def unpair_id(self, id_):
        xpub = self.xpub_by_id(id_)
        if xpub:
            self.unpair_xpub(xpub)
        else:
            self._close_client(id_)

    def _close_client(self, id_):
        client = self.client_lookup(id_)
        self.clients.pop(client, None)
        if client:
            client.close()

    def pair_xpub(self, xpub, id_):
        with self.lock:
            self.xpub_ids[xpub] = id_

    def client_lookup(self, id_):
        with self.lock:
            for client, (path, client_id) in self.clients.items():
                if client_id == id_:
                    return client
        return None

    def client_by_id(self, id_):
        '''Returns a client for the device ID if one is registered.  If a device is wiped or in
        bootloader mode pairing is impossible; in such cases we communicate by device ID
        and not wallet.
        '''
        self.scan_devices()
        return self.client_lookup(id_)

    def client_for_keystore(self, hardware, keystore, force_pair):
        logger.debug("getting client for keystore")
        handler = keystore.handler
        if handler is None:
            raise Exception(_("Handler not found for") + ' ' + hardware.name + '\n' +
                            _("A library is probably missing."))
        handler.update_status(False)
        devices = self.scan_devices()
        xpub = keystore.xpub
        derivation = keystore.get_derivation()
        client = self.client_by_xpub(hardware, xpub, handler, devices)
        if client is None and force_pair:
            info = self.select_device(hardware, handler, keystore, devices)
            client = self.force_pair_xpub(hardware, handler, info, xpub, derivation, devices)
        if client:
            handler.update_status(True)
        return client

    def client_by_xpub(self, hardware, xpub, handler, devices):
        _id = self.xpub_id(xpub)
        client = self.client_lookup(_id)
        if client:
            # An unpaired client might have another wallet's handler
            # from a prior scan.  Replace to fix dialog parenting.
            client.handler = handler
            return client

        for device in devices:
            if device.id_ == _id:
                return self.create_client(device, handler, hardware)

    def force_pair_xpub(self, hardware, handler, info, xpub, derivation, devices):
        # The wallet has not been previously paired, so let the user
        # choose an unpaired device and compare its first address.
        xtype = bip32.xpub_type(xpub)
        client = self.client_lookup(info.device.id_)
        if client and client.is_pairable():
            # See comment above for same code
            client.handler = handler
            # This will trigger a PIN/passphrase entry request
            try:
                client_xpub = client.get_xpub(derivation, xtype)
            except (UserCancelled, RuntimeError):
                # Bad / cancelled PIN / passphrase
                client_xpub = None
            if client_xpub == xpub:
                self.pair_xpub(xpub, info.device.id_)
                return client

        # The user input has wrong PIN or passphrase, or cancelled input,
        # or it is not pairable
        raise DeviceUnpairableError(
            _('ElectrumSV cannot pair with your {}.\n\nBefore you request bitcoins to be '
              'sent to addresses in this wallet, ensure you can pair with your device, '
              'or that you have its seed (and passphrase, if any). Otherwise all '
              'bitcoins you receive will be unspendable.').format(hardware.device))

    def unpaired_device_infos(self, handler, hardware, devices=None):
        '''Returns a list of DeviceInfo objects: one for each connected,
        unpaired device accepted by the hardware.'''
        if not hardware.libraries_available:
            raise RuntimeError(hardware.get_library_not_available_message())
        if devices is None:
            devices = self.scan_devices()
        devices = [dev for dev in devices if not self.xpub_by_id(dev.id_)]
        infos = []
        for device in devices:
            if device.product_key not in hardware.DEVICE_IDS:
                continue
            try:
                client = self.create_client(device, handler, hardware)
            except Exception as e:
                logger.debug('failed to create client for %s at %s: %r',
                             hardware.name, device.path, e)
                continue
            if not client:
                continue
            infos.append(DeviceInfo(device, client.label(), client.is_initialized()))

        return infos

    def select_device(self, hardware, handler, keystore, devices=None):
        '''Ask the user to select a device to use if there is more than one, and return the
        DeviceInfo for the device.
        '''
        while True:
            infos = self.unpaired_device_infos(handler, hardware, devices)
            if infos:
                break
            msg = _('Please insert your {}.  Verify the cable is connected and that no other '
                    'application is using it.\n\nTry to connect again?').format(hardware.device)
            if not handler.yes_no_question(msg):
                raise UserCancelled()
            devices = None
        if len(infos) == 1:
            return infos[0]
        # select device by label
        for info in infos:
            if info.label == keystore.label:
                return info
        msg = _("Please select which {} device to use:").format(hardware.device)
        descriptions = ['{} ({})'
                        .format(info.label, _("initialized") if info.initialized else _("wiped"))
                        for info in infos]
        c = handler.query_choice(msg, descriptions)
        if c is None:
            raise UserCancelled()
        info = infos[c]
        # save new label
        keystore.set_label(info.label)
        if handler.win.wallet:
            handler.win.wallet.save_keystore()
        return info

    def _scan_devices_with_hid(self):
        try:
            import hid
        except ImportError:
            return []

        with self.hid_lock:
            hid_list = hid.enumerate(0, 0)

        devices = []
        for d in hid_list:
            product_key = (d['vendor_id'], d['product_id'])
            if product_key in self.recognised_hardware:
                # Older versions of hid don't provide interface_number
                interface_number = d.get('interface_number', -1)
                usage_page = d['usage_page']
                id_ = d['serial_number']
                if len(id_) == 0:
                    id_ = str(d['path'])
                id_ += str(interface_number) + str(usage_page)
                devices.append(Device(path=d['path'],
                                      interface_number=interface_number,
                                      id_=id_,
                                      product_key=product_key,
                                      usage_page=usage_page,
                                      transport_ui_string='hid'))
        return devices

    def scan_devices(self):
        logger.debug("scanning devices...")

        # First see what's connected that we know about
        devices = self._scan_devices_with_hid()

        # Let hardware handlers enumerate devices we don't know about
        for f in self.enumerate_func:
            try:
                new_devices = f()
            except Exception as e:
                logger.error('custom device enum failed. func %s, error %s', f, e)
            else:
                devices.extend(new_devices)

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
