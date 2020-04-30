# ElectrumSV - lightweight Bitcoin client
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

from electrumsv.app_state import app_state
from electrumsv.i18n import _


class Extension(object):

    def __init__(self, setting, name, description):
        self.setting = setting
        self.name = name
        self.description = description

    def is_enabled(self):
        return app_state.config.get('use_' + self.setting, False)

    def set_enabled(self, enabled):
        return app_state.config.set_key('use_' + self.setting, bool(enabled))


class CosignerPoolExtension(Extension):

    def set_enabled(self, enabled):
        result = super().set_enabled(enabled)
        app_state.app.cosigner_pool.on_enabled_changed()
        return result


class LabelSyncExtension(Extension):

    def set_enabled(self, enabled):
        result = super().set_enabled(enabled)
        app_state.app.label_sync.on_enabled_changed()
        return result


cosigner_pool = CosignerPoolExtension(
    'cosigner_pool', _('Cosigner Pool'),
    '\n'.join([
        _("This plugin facilitates the use of multi-signatures wallets."),
        _("It sends and receives partially signed transactions from/to your cosigner wallet."),
        _("Transactions are encrypted and stored on a remote server.")
    ]))

label_sync = LabelSyncExtension(
    'labels', _('Label Sync'),
    _("Older wallets may have descriptions for addresses and transactions that were "
    "encrypted before being uploaded to the Electrum Core 'label sync' server. "
    "ElectrumSV now no longer has a naive JSON storage for it's account data, so "
    "it has no way to store any descriptions which the account does not know of the "
    "address or transaction for."))

extensions = [
    cosigner_pool,
    label_sync,
]
