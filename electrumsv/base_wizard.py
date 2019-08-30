# -*- coding: utf-8 -*-
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2016 Thomas Voegtlin
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

import os
from typing import Optional, Any, List, Tuple

from bitcoinx import bip32_is_valid_chain_string

from . import bitcoin
from . import keystore
from .app_state import app_state
from .device import DeviceInfo
from .i18n import _
from .keystore import bip44_derivation_cointype, KeyStore
from .logs import logs
from .storage import WalletStorage
from .wallet import (
    ParentWallet, ImportedAddressWallet, ImportedPrivkeyWallet, Multisig_Wallet,
    WalletTypes, Standard_Wallet
)


logger = logs.get_logger('wizard')


DeviceList = List[Tuple[str, DeviceInfo]]


class BaseWizard(object):
    def __init__(self, storage: WalletStorage) -> None:
        super(BaseWizard, self).__init__()

        self.storage = storage
        self.parent_wallet: Optional[ParentWallet] = None
        self.stack: List[Any] = []
        self.plugin: Optional[Any] = None
        self.keystores: List[KeyStore] = []
        self.seed_type: Optional[str] = None

    def run(self, *args) -> None:
        action = args[0]
        args = args[1:]
        self.stack.append((action, args))
        if not action:
            return
        if type(action) is tuple:
            self.plugin, action = action
        if self.plugin and hasattr(self.plugin, action):
            f = getattr(self.plugin, action)
            f(self, *args)
        elif hasattr(self, action):
            f = getattr(self, action)
            f(*args)
        else:
            raise Exception("unknown action", action)

    def can_go_back(self) -> bool:
        return len(self.stack) > 1

    def go_back(self) -> None:
        if not self.can_go_back():
            return
        self.stack.pop()
        action, args = self.stack.pop()
        self.run(action, *args)

    def new(self) -> None:
        name = os.path.basename(self.storage.get_path())
        title = _("Create") + ' ' + name
        message = '\n'.join([
            _("What kind of wallet do you want to create?")
        ])
        choices = [
            (WalletTypes.STANDARD,  _("Standard wallet")),
            (WalletTypes.MULTISIG,  _("Multi-signature wallet")),
            (WalletTypes.IMPORTED,  _("Import Bitcoin addresses or private keys")),
        ]
        self.choice_dialog(title=title, message=message, choices=choices,
                           run_next=self.on_wallet_type)

    def on_wallet_type(self, choice: str) -> None:
        self.wallet_type = choice
        if choice == 'standard':
            action = 'choose_keystore'
        elif choice == 'multisig':
            action = 'choose_multisig'
        elif choice == 'imported':
            action = 'import_addresses_or_keys'
        self.run(action)

    def choose_multisig(self) -> None:
        def on_multisig(m, n):
            self.multisig_type = "%dof%d"%(m, n)
            self.n = n
            self.run('choose_keystore')
        self.multisig_dialog(run_next=on_multisig)

    def choose_keystore(self) -> None:
        assert self.wallet_type in ['standard', 'multisig']
        i = len(self.keystores)
        title = (_('Add cosigner') + ' (%d of %d)'%(i+1, self.n)
                 if self.wallet_type=='multisig' else _('Keystore'))
        if self.wallet_type =='standard' or i==0:
            message = _('Do you want to create a new seed, or to restore a '
                        'wallet using an existing seed?')
            choices = [
                ('create_standard_seed', _('Create a new seed')),
                ('restore_from_seed', _('I already have a seed')),
                ('restore_from_key', _('Use public or private keys')),
                ('choose_hw_device',  _('Use a hardware device')),
            ]
        else:
            message = _('Add a cosigner to your multi-sig wallet')
            choices = [
                ('restore_from_key', _('Enter cosigner key')),
                ('restore_from_seed', _('Enter cosigner seed')),
                ('choose_hw_device',  _('Cosign with hardware device')),
            ]

        self.choice_dialog(title=title, message=message, choices=choices, run_next=self.run)

    def import_addresses_or_keys(self) -> None:
        v = lambda x: keystore.is_address_list(x) or keystore.is_private_key_list(x)
        title = _("Import Bitcoin Addresses")
        message = _("Enter a list of Bitcoin addresses (this will create a "
                    "watching-only wallet), or a list of private keys.")
        self.add_xpub_dialog(title=title, message=message, run_next=self.on_import,
                             is_valid=v, allow_multi=True)

    def on_import(self, text: str) -> None:
        if keystore.is_address_list(text):
            self.parent_wallet = ParentWallet.as_legacy_wallet_container(self.storage)
            ImportedAddressWallet.from_text(self.parent_wallet, text)

            self.request_password(run_next=self.on_password)
        elif keystore.is_private_key_list(text):
            self.parent_wallet = ParentWallet.as_legacy_wallet_container(self.storage)
            legacy_wallet = ImportedPrivkeyWallet.from_text(self.parent_wallet, text)
            # We grab references to these, as we will be encrypting them if a password is set.
            self.keystores = legacy_wallet.get_keystores()

            self.request_password(run_next=self.on_password)
        self.terminate()

    def restore_from_key(self) -> None:
        if self.wallet_type == 'standard':
            v = keystore.is_master_key
            title = _("Create keystore from a master key")
            message = ' '.join([
                _("To create a watching-only wallet, please enter your master "
                  "public key (xpub/ypub/zpub)."),
                _("To create a spending wallet, please enter a master private "
                  "key (xprv/yprv/zprv).")
            ])
            self.add_xpub_dialog(title=title, message=message,
                                 run_next=self.on_restore_from_key, is_valid=v)
        else:
            i = len(self.keystores) + 1
            self.add_cosigner_dialog(index=i, run_next=self.on_restore_from_key,
                                     is_valid=keystore.is_bip32_key)

    def on_restore_from_key(self, text: str) -> None:
        k = keystore.from_master_key(text)
        self.on_keystore(k)

    def choose_hw_device(self) -> None:
        title = _('Hardware Keystore')
        # scan devices
        devices: DeviceList = []
        devmgr = app_state.device_manager
        debug_msg = ''
        # This needs to be done before the scan, otherwise the devices will not be loaded.
        supported_devices = devmgr.supported_devices()
        try:
            scanned_devices = devmgr.scan_devices()
        except:
            logger.exception(f'error scanning devices')
        else:
            for device_kind, plugin in supported_devices.items():
                # plugin init errored?
                if isinstance(plugin, Exception):
                    tail = '\n    '.join([_('You might have an incompatible library.'), '']
                                         + str(plugin).splitlines())
                    debug_msg += f'  {device_kind}: (error loding plugin)\n{tail}\n'
                    continue

                try:
                    # FIXME: side-effect: unpaired_device_info sets client.handler
                    u = devmgr.unpaired_device_infos(None, plugin, devices=scanned_devices)
                    devices += [(device_kind, x) for x in u]
                except Exception as e:
                    logger.exception(f'error getting device infos for {device_kind}')
                    tail = '\n    '.join([''] + str(e).splitlines())
                    debug_msg += f'  {device_kind}: (error getting device infos)\n{tail}\n'

        if not debug_msg:
            debug_msg = '  {}'.format(_('No exceptions encountered.'))
        if not devices:
            msg = ''.join([
                _('No hardware device detected.') + '\n',
                _('To trigger a rescan, press \'Next\'.') + '\n\n',
                _('If your device is not detected on Windows, go to "Settings", "Devices", '
                  '"Connected devices", and do "Remove device". '
                  'Then, plug your device again.') + ' ',
                _('On Linux, you might have to add a new permission to your udev rules.') + '\n\n',
                _('Debug message') + '\n',
                debug_msg
            ])
            self.confirm_dialog(title=title, message=msg,
                                run_next= lambda x: self.choose_hw_device())
            return
        # select device
        self.devices = devices
        choices = []
        for name, info in devices:
            state = _("initialized") if info.initialized else _("wiped")
            label = info.label or _("An unnamed {}").format(name)
            choices.append(((name, info), f"{label} [{name}, {state}]"))
        msg = _('Select a device') + ':'
        self.choice_dialog(title=title, message=msg, choices=choices, run_next=self.on_device)

    def on_device(self, name: str, device_info: DeviceInfo) -> None:
        self.plugin = app_state.device_manager.get_plugin(name)
        try:
            self.plugin.setup_device(device_info, self)
        except OSError as e:
            self.show_error(_('We encountered an error while connecting to your device:')
                            + '\n' + str(e) + '\n'
                            + _('To try to fix this, we will now re-pair with your device.') + '\n'
                            + _('Please try again.'))
            app_state.device_manager.unpair_id(device_info.device.id_)
            self.choose_hw_device()
            return
        except Exception as e:
            self.show_error(str(e))
            self.choose_hw_device()
            return
        f = lambda x: self.run('on_hw_derivation', name, device_info, str(x))
        if self.wallet_type=='multisig':
            # There is no general standard for HD multisig.
            # This is partially compatible with BIP45; assumes index=0
            default_derivation = "m/45'/0"
        else:
            default_derivation = bip44_derivation_cointype(0, 0)
        self.derivation_dialog(f, default_derivation)

    def derivation_dialog(self, f, default_derivation: str) -> None:
        message = '\n'.join([
            _('Enter your wallet derivation here.  If you are not sure what this is, '
              'leave this field unchanged.\n'),
            _("The default value of {} is the default derivation for {} wallets.  "
              "This matches BTC wallet addresses and most other BSV wallet software.")
            .format(default_derivation, self.wallet_type),
            _("To match BCH wallet addresses use m/44'/145'/0'"),
        ])
        self.line_dialog(run_next=f,
                         title=_('Derivation for {} wallet').format(self.wallet_type),
                         message=message, default=default_derivation,
                         test=bip32_is_valid_chain_string)

    def on_hw_derivation(self, name: str, device_info: DeviceInfo, derivation: str) -> None:
        assert self.plugin is not None
        try:
            mpk = self.plugin.get_master_public_key(device_info.device.id_, derivation, self)
        except Exception as e:
            self.show_error(e)
            return
        d = {
            'type': 'hardware',
            'hw_type': name,
            'derivation': derivation,
            'xpub': mpk.to_extended_key_string(),
            'label': device_info.label,
        }
        k = app_state.device_manager.create_keystore(d)
        self.on_keystore(k)

    def passphrase_dialog(self, run_next) -> None:
        title = _('Seed extension')
        message = '\n'.join([
            _('You may extend your seed with custom words.'),
            _('Your seed extension must be saved together with your seed.'),
        ])
        warning = '\n'.join([
            _('Note that this is NOT your encryption password.'),
            _('If you do not know what this is, leave this field empty.'),
        ])
        self.line_dialog(title=title, message=message, warning=warning, default='',
                         test=lambda x:True, run_next=run_next)

    def restore_from_seed(self) -> None:
        self.opt_bip39 = True
        self.opt_ext = True
        test = bitcoin.is_seed if self.wallet_type == 'standard' else bitcoin.is_new_seed
        self.restore_seed_dialog(run_next=self.on_restore_seed, test=test)

    def on_restore_seed(self, seed: str, is_bip39: bool, is_ext: bool) -> None:
        self.seed_type = 'bip39' if is_bip39 else bitcoin.seed_type(seed)
        if self.seed_type == 'bip39':
            f=lambda passphrase: self.on_restore_bip39(seed, passphrase)
            if is_ext:
                self.passphrase_dialog(run_next=f)
            else:
                f('')
        elif self.seed_type in ['standard']:
            f = lambda passphrase: self.run('create_keystore', seed, passphrase)
            if is_ext:
                self.passphrase_dialog(run_next=f)
            else:
                f('')
        elif self.seed_type == 'old':
            self.run('create_keystore', seed, '')
        else:
            raise Exception('Unknown seed type', self.seed_type)

    def on_restore_bip39(self, seed: str, passphrase: Optional[str]) -> None:
        f = lambda x: self.run('on_bip44', seed, passphrase, str(x))
        self.derivation_dialog(f, bip44_derivation_cointype(0, 0))

    def create_keystore(self, seed: str, passphrase: Optional[str]) -> None:
        k = keystore.from_seed(seed, passphrase, self.wallet_type == 'multisig')
        self.on_keystore(k)

    def on_bip44(self, seed: str, passphrase: Optional[str], derivation: str) -> None:
        k = keystore.from_bip39_seed(seed, passphrase, derivation)
        self.on_keystore(k)

    def on_keystore(self, k: keystore.KeyStore) -> None:
        if self.wallet_type == 'standard':
            self.keystores.append(k)
            self.run('create_wallet')
        elif self.wallet_type == 'multisig':
            assert isinstance(k, keystore.Xpub)
            if k.xpub in [x.xpub for x in self.keystores]:
                self.show_error(_('Error: duplicate master public key'))
                self.run('choose_keystore')
                return
            self.keystores.append(k)
            if len(self.keystores) == 1:
                xpub = k.get_master_public_key()
                self.stack = []
                self.run('show_xpub_and_add_cosigners', xpub)
            elif len(self.keystores) < self.n:
                self.run('choose_keystore')
            else:
                self.run('create_wallet')

    def create_wallet(self) -> None:
        if any(k.may_have_password() for k in self.keystores):
            self.request_password(run_next=self.on_password)
        else:
            self.on_password(None)

    def on_password(self, password: Optional[str]) -> None:
        if self.wallet_type == 'standard':
            self.parent_wallet = ParentWallet.as_legacy_wallet_container(self.storage)
            keystore_usage = self.parent_wallet.add_keystore(self.keystores[0].dump())
            Standard_Wallet.create_within_parent(self.parent_wallet,
                keystore_usage=[ keystore_usage ])
        elif self.wallet_type == 'multisig':
            self.parent_wallet = ParentWallet.as_legacy_wallet_container(self.storage)
            keystore_usages = []
            for i, k in enumerate(self.keystores):
                keystore_usage = self.parent_wallet.add_keystore(k.dump())
                keystore_usage['name'] = f'x{i+1}/'
                keystore_usages.append(keystore_usage)
            Multisig_Wallet.create_within_parent(self.parent_wallet,
                keystore_usage=keystore_usages, wallet_type=self.multisig_type)

        if self.parent_wallet is not None and password:
            self.parent_wallet.set_initial_password(password)

    def show_xpub_and_add_cosigners(self, xpub) -> None:
        self.show_xpub_dialog(xpub=xpub, run_next=lambda x: self.run('choose_keystore'))

    def create_standard_seed(self) -> None:
        self.create_seed('standard')

    def create_seed(self, seed_type: str) -> None:
        from . import mnemonic
        self.seed_type = seed_type
        seed = mnemonic.Mnemonic('en').make_seed(self.seed_type)
        self.opt_bip39 = False
        f = lambda x: self.request_passphrase(seed, x)
        self.show_seed_dialog(run_next=f, seed_text=seed)

    def request_passphrase(self, seed: str, opt_passphrase: Optional[str]) -> None:
        if opt_passphrase:
            f = lambda x: self.confirm_seed(seed, x)
            self.passphrase_dialog(run_next=f)
        else:
            self.run('confirm_seed', seed, '')

    def confirm_seed(self, seed: str, passphrase: Optional[str]) -> None:
        f = lambda x: self.confirm_passphrase(seed, passphrase)
        self.confirm_seed_dialog(run_next=f, test=lambda x: x==seed)

    def confirm_passphrase(self, seed: str, passphrase: Optional[str]) -> None:
        f = lambda x: self.run('create_keystore', seed, x)
        if passphrase:
            title = _('Confirm Seed Extension')
            message = '\n'.join([
                _('Your seed extension must be saved together with your seed.'),
                _('Please type it here.'),
            ])
            self.line_dialog(run_next=f, title=title, message=message, default='',
                             test=lambda x: x==passphrase)
        else:
            f('')

    def add_cosigner_dialog(self, run_next, index, is_valid):
        raise NotImplementedError

    def add_xpub_dialog(self, title, message, is_valid, run_next, allow_multi=False):
        raise NotImplementedError

    def choice_dialog(self, title, message, choices, run_next) -> None:
        raise NotImplementedError

    def confirm_dialog(self, title, message, run_next):
        raise NotImplementedError

    def confirm_seed_dialog(self, run_next, test):
        raise NotImplementedError

    def line_dialog(self, run_next, title, message, default, test, warning=''):
        raise NotImplementedError

    def multisig_dialog(self, run_next) -> None:
        raise NotImplementedError

    def restore_seed_dialog(self, run_next, test):
        raise NotImplementedError

    def request_password(self, run_next):
        raise NotImplementedError

    def show_error(self, msg, parent=None):
        raise NotImplementedError

    def show_seed_dialog(self, run_next, seed_text):
        raise NotImplementedError

    def show_xpub_dialog(self, xpub, run_next):
        raise NotImplementedError

    def terminate(self):
        raise NotImplementedError
