# ElectrumSV - lightweight Bitcoin client
# Copyright (C) 2012 thomasv@gitorious
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

'''ElectrumSV Preferences dialog.'''

from functools import partial
from typing import Optional, TYPE_CHECKING

from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import (
    QCheckBox, QComboBox, QDialog, QGroupBox, QHBoxLayout, QLabel, QSpinBox, QTabWidget,
    QVBoxLayout, QWidget
)

from electrumsv import qrscanner
from electrumsv.app_state import app_state
from electrumsv.constants import (MAXIMUM_TXDATA_CACHE_SIZE_MB, MINIMUM_TXDATA_CACHE_SIZE_MB,
    ScriptType)
from electrumsv.extensions import label_sync
from electrumsv.extensions import extensions
from electrumsv.i18n import _, languages
import electrumsv.web as web
from electrumsv.wallet import AbstractAccount, Wallet

from .amountedit import BTCSatsByteEdit
from .util import Buttons, CloseButton, FormSectionWidget, HelpButton, HelpLabel, MessageBox

if TYPE_CHECKING:
    from electrumsv.gui.qt.main_window import ElectrumWindow


class PreferencesDialog(QDialog):
    def __init__(self, main_window: 'ElectrumWindow', wallet: Wallet,
            account: Optional[AbstractAccount]=None):
        '''The preferences dialog has a account tab only if account is given.'''
        super().__init__(main_window, Qt.WindowSystemMenuHint | Qt.WindowTitleHint |
            Qt.WindowCloseButtonHint)
        self.setWindowTitle(_('Preferences'))
        self._main_window = main_window
        self.lay_out(wallet, account)
        self.initial_language = app_state.config.get('language', None)

    def accept(self) -> None:
        if app_state.fx:
            app_state.fx.trigger_history_refresh()
        # Qt on Mac has a bug with "modalSession has been exited prematurely" That means
        # you cannot create a modal dialog when exiting a model dialog, such as in the
        # finished signal.  So we do this in the accept() function instead.
        if self.initial_language != app_state.config.get('language', None):
            MessageBox.show_warning(
                _('Restart ElectrumSV to activate your updated language setting'),
                title=_('Success'), parent=self)
        super().accept()

    def lay_out(self, wallet: Wallet, account: Optional[AbstractAccount]) -> None:
        tabs_info = [
            (self.general_widgets, _('General')),
            (self.tx_widgets, _('Transactions')),
            (self.fiat_widgets, _('Fiat')),
            (partial(self.extensions_widgets, account), _('Extensions')),
        ]
        tabs_info.append((partial(self.wallet_widgets, wallet), _('Wallet')))
        if account is not None:
            tabs_info.append((partial(self.account_widgets, account), _('Account')))
        tabs_info.append((self.network_widgets, _('Network')))

        tabs = QTabWidget()
        tabs.setUsesScrollButtons(False)
        for widget_func, name in tabs_info:
            tab = QWidget()
            widget_func(tab)
            tabs.addTab(tab, name)

        vbox = QVBoxLayout()
        vbox.addWidget(tabs)
        vbox.addStretch(1)
        vbox.addLayout(Buttons(CloseButton(self)))
        self.setLayout(vbox)

    def tx_widgets(self, tab: QWidget) -> None:
        def on_customfee(_text):
            amt = customfee_e.get_amount()
            m = int(amt * 1000.0) if amt is not None else None
            app_state.config.set_key('customfee', m)
            app_state.app.custom_fee_changed.emit()

        customfee_e = BTCSatsByteEdit()
        customfee_e.setAmount(app_state.config.custom_fee_rate() / 1000.0
                              if app_state.config.has_custom_fee_rate() else None)
        customfee_e.textChanged.connect(on_customfee)
        # customfee_label = HelpLabel(_('Custom Fee Rate'),
        #                             _('Custom Fee Rate in Satoshis per byte'))

        unconf_cb = QCheckBox(_('Spend only confirmed coins'))
        unconf_cb.setToolTip(_('Spend only confirmed inputs.'))
        unconf_cb.setChecked(app_state.config.get('confirmed_only', False))
        def on_unconf(state):
            app_state.config.set_key('confirmed_only', state != Qt.Unchecked)
        unconf_cb.stateChanged.connect(on_unconf)

        options_box = QGroupBox()
        options_vbox = QVBoxLayout()
        options_box.setLayout(options_vbox)
        options_vbox.addWidget(unconf_cb)

        form = FormSectionWidget(minimum_label_width=120)
        form.add_row(_('Custom Fee Rate'), customfee_e)
        form.add_row(_("Options"), options_box, True)

        vbox = QVBoxLayout()
        vbox.addWidget(form)
        vbox.addStretch(1)
        tab.setLayout(vbox)

    def general_widgets(self, tab: QWidget) -> None:
        # language
        lang_modifiable = app_state.config.is_modifiable('language')
        lang_pairs = sorted((code, language) for language, code in languages.items())
        language_names, language_keys = zip(*lang_pairs)

        # lang_label = HelpLabel(_('Language') + ':',
        #                        _('Select which language is used in the GUI (after restart).'))
        # lang_label.setEnabled(lang_modifiable)

        lang_combo = QComboBox()
        lang_combo.setEnabled(lang_modifiable)
        lang_combo.addItems(language_names)
        try:
            index = language_keys.index(app_state.config.get("language", ''))
        except ValueError:
            index = 0
        lang_combo.setCurrentIndex(index)
        def on_lang(index):
            lang_request = language_keys[index]
            if lang_request != app_state.config.get('language'):
                app_state.config.set_key("language", lang_request, True)
        lang_combo.currentIndexChanged.connect(on_lang)

        nz_modifiable = app_state.config.is_modifiable('num_zeros')
        # nz_label = HelpLabel(_('Zeros after decimal point') + ':',
        #                      _('Number of zeros displayed after the decimal point.  '
        #                        'For example, if set to 2, "1." will be displayed as "1.00"'))
        # nz_label.setEnabled(nz_modifiable)
        nz = QSpinBox()
        nz.setMinimum(0)
        nz.setMaximum(app_state.decimal_point)
        nz.setValue(app_state.num_zeros)
        nz.setEnabled(nz_modifiable)
        def on_nz():
            value = nz.value()
            if app_state.num_zeros != value:
                app_state.num_zeros = value
                app_state.config.set_key('num_zeros', value, True)
                app_state.app.num_zeros_changed.emit()
        nz.valueChanged.connect(on_nz)

        # unit_label = HelpLabel(_('Base unit') + ':', '\n'.join((
        #     _('Base unit of display in the application.'),
        #     '1 BSV = 1,000 mBSV = 1,000,000 bits.',
        # )))
        unit_combo = QComboBox()
        unit_combo.addItems(app_state.base_units)
        unit_combo.setCurrentIndex(app_state.base_units.index(app_state.base_unit()))
        def on_unit(index):
            app_state.set_base_unit(app_state.base_units[index])
            nz.setMaximum(app_state.decimal_point)
        unit_combo.currentIndexChanged.connect(on_unit)

        msg = _('Choose which online block explorer to use for functions that open a web browser')
        # block_ex_label = HelpLabel(_('Online Block Explorer') + ':', msg)
        block_explorers = web.BE_sorted_list()
        block_ex_combo = QComboBox()
        block_ex_combo.addItems(block_explorers)
        block_ex_combo.setCurrentIndex(block_ex_combo.findText(
            web.BE_from_config(app_state.config)))
        def on_be(index):
            app_state.config.set_key('block_explorer', block_explorers[index], True)
        block_ex_combo.currentIndexChanged.connect(on_be)

        # qr_label = HelpLabel(_('Video Device') + ':',
        #                      _("Install the zbar package to enable this."))
        qr_combo = QComboBox()
        qr_combo.addItem("Default", "default")
        system_cameras = qrscanner.find_system_cameras()
        for camera, device in system_cameras.items():
            qr_combo.addItem(camera, device)
        qr_combo.setCurrentIndex(qr_combo.findData(app_state.config.get("video_device")))
        qr_combo.setEnabled(qrscanner.libzbar is not None)
        def on_video_device(index):
            app_state.config.set_key("video_device", qr_combo.itemData(index), True)
        qr_combo.currentIndexChanged.connect(on_video_device)

        updatecheck_box = QGroupBox()
        updatecheck_vbox = QVBoxLayout()
        updatecheck_box.setLayout(updatecheck_vbox)
        # The main checkbox, which turns update checking on or off completely.
        updatecheck_cb = QCheckBox(_("Automatically check for software updates"))
        updatecheck_cb.setChecked(app_state.config.get('check_updates', True))
        def on_set_updatecheck(v):
            app_state.config.set_key('check_updates', v == Qt.Checked, save=True)
        updatecheck_cb.stateChanged.connect(on_set_updatecheck)
        updatecheck_vbox.addWidget(updatecheck_cb)
        # The secondary checkbox, which determines if unstable releases result in notifications.
        updatecheck_unstable_cb = QCheckBox(_("Ignore unstable releases"))
        updatecheck_unstable_cb.setChecked(
            app_state.config.get('check_updates_ignore_unstable', True))
        def on_set_updatecheck_unstable(v):
            app_state.config.set_key('check_updates_ignore_unstable', v == Qt.Checked, save=True)
        updatecheck_unstable_cb.stateChanged.connect(on_set_updatecheck_unstable)
        updatecheck_vbox.addWidget(updatecheck_unstable_cb)

        form = FormSectionWidget(minimum_label_width=130)
        form.add_row(_('Language'), lang_combo)
        form.add_row(_('Zeros after decimal point'), nz)
        form.add_row(_('Base unit'), unit_combo)
        form.add_row(_('Online block explorer'), block_ex_combo)
        form.add_row(_('Video device'), qr_combo)
        form.add_row(_('Software updates'), updatecheck_box)

        vbox = QVBoxLayout()
        vbox.addWidget(form)
        vbox.addStretch(1)
        tab.setLayout(vbox)

    def fiat_widgets(self, tab: QWidget) -> None:
        # Fiat Currency
        hist_checkbox = QCheckBox(_('Show historical rates'))
        fiat_balance_checkbox = QCheckBox(_('Show Fiat balance for addresses'))
        ccy_combo = QComboBox()
        ex_combo = QComboBox()

        # FIXME: note main window tabs are not correctly hooked up to FX rate changes
        # to refresh when an update comes in from twiddling here

        def update_currencies():
            fx = app_state.fx
            if fx:
                currencies = sorted(fx.get_currencies())
                ccy_combo.clear()
                ccy_combo.addItems([_('None')] + currencies)
                if fx.is_enabled():
                    ccy_combo.setCurrentIndex(ccy_combo.findText(fx.get_currency()))

        def update_history_cb():
            fx = app_state.fx
            if fx:
                hist_checkbox.setChecked(fx.get_history_config())
                hist_checkbox.setEnabled(fx.is_enabled())

        def update_fiat_balance_cb():
            fx = app_state.fx
            if fx:
                fiat_balance_checkbox.setChecked(fx.get_fiat_address_config())

        def update_exchanges():
            fx = app_state.fx
            if fx:
                b = fx.is_enabled()
                ex_combo.setEnabled(b)
                if b:
                    h = fx.get_history_config()
                    c = fx.get_currency()
                    exchanges = fx.get_exchanges_by_ccy(c, h)
                else:
                    exchanges = fx.get_exchanges_by_ccy('USD', False)
                ex_combo.clear()
                ex_combo.addItems(sorted(exchanges))
                ex_combo.setCurrentIndex(ex_combo.findText(fx.config_exchange()))

        def on_currency(index):
            fx = app_state.fx
            if fx:
                enabled = index != 0
                fx.set_enabled(enabled)
                if enabled:
                    fx.set_currency(ccy_combo.currentText())
                update_history_cb()
                update_exchanges()
                app_state.app.fiat_ccy_changed.emit()

        def on_exchange(_index):
            exchange = str(ex_combo.currentText())
            fx = app_state.fx
            if fx and fx.is_enabled() and exchange and exchange != fx.exchange.name():
                fx.set_exchange(exchange)

        def on_history(state):
            fx = app_state.fx
            if fx:
                fx.set_history_config(state == Qt.Checked)
                update_exchanges()
                app_state.app.fiat_history_changed.emit()

        def on_fiat_balance(state):
            fx = app_state.fx
            if fx:
                fx.set_fiat_address_config(state == Qt.Checked)
                app_state.app.fiat_balance_changed.emit()

        update_currencies()
        update_history_cb()
        update_fiat_balance_cb()
        update_exchanges()

        ccy_combo.currentIndexChanged.connect(on_currency)
        hist_checkbox.stateChanged.connect(on_history)
        fiat_balance_checkbox.stateChanged.connect(on_fiat_balance)
        ex_combo.currentIndexChanged.connect(on_exchange)

        options_box = QGroupBox()
        options_vbox = QVBoxLayout()
        options_box.setLayout(options_vbox)
        options_vbox.addWidget(hist_checkbox)
        options_vbox.addWidget(fiat_balance_checkbox)

        extension_form = FormSectionWidget()
        extension_form.add_row(_('Currency'), ccy_combo)
        extension_form.add_row(_('Source'), ex_combo)
        extension_form.add_row(_('Options'), options_box, True)

        vbox = QVBoxLayout()
        vbox.addWidget(extension_form)
        vbox.addStretch(1)
        tab.setLayout(vbox)

    def extensions_widgets(self, account: Optional[AbstractAccount], tab: QWidget) -> None:
        def cb_clicked(extension, settings_widget, checked):
            extension.set_enabled(checked)
            if settings_widget:
                settings_widget.setEnabled(checked)

        vbox = QVBoxLayout()
        extension_form = FormSectionWidget()
        for extension in extensions:
            cb = QCheckBox(_("Enabled"))
            cb.setChecked(extension.is_enabled())
            help_widget = HelpButton(extension.description)
            field_layout = QHBoxLayout()
            field_layout.addWidget(cb)
            field_layout.addStretch(1)
            if extension is label_sync and account:
                settings_widget = app_state.app.label_sync.settings_widget(self, account)
                settings_widget.setEnabled(extension.is_enabled())
                field_layout.addWidget(settings_widget)
                cb.clicked.connect(partial(cb_clicked, extension, settings_widget))
            else:
                cb.clicked.connect(partial(cb_clicked, extension, None))
            field_layout.addWidget(help_widget)
            extension_form.add_row(extension.name, field_layout, True)

        vbox.addWidget(extension_form)
        vbox.addStretch(1)
        tab.setLayout(vbox)

    def wallet_widgets(self, wallet: Wallet, tab: QWidget) -> None:
        usechange_cb = QCheckBox(_('Use change addresses'))
        usechange_cb.setChecked(wallet.get_use_change())
        usechange_cb.setEnabled(app_state.config.is_modifiable('use_change'))
        usechange_cb.setToolTip(
            _('Using a different change key each time improves your privacy by '
              'making it more difficult for others to analyze your transactions.')
        )
        def on_usechange(state):
            usechange_result = state == Qt.Checked
            if wallet.get_use_change() != usechange_result:
                wallet.set_use_change(usechange_result)
                multiple_cb.setEnabled(wallet.get_use_change())
        usechange_cb.stateChanged.connect(on_usechange)

        multiple_cb = QCheckBox(_('Use multiple change addresses'))
        multiple_cb.setChecked(wallet.get_multiple_change())
        multiple_cb.setEnabled(wallet.get_use_change())
        multiple_cb.setToolTip('\n'.join([
            _('In some cases, use up to 3 change keys in order to break '
              'up large coin amounts and obfuscate the recipient key.'),
            _('This may result in higher transactions fees.')
        ]))
        def on_multiple(state):
            multiple = state == Qt.Checked
            if wallet.get_multiple_change() != multiple:
                wallet.set_multiple_change(multiple)
        multiple_cb.stateChanged.connect(on_multiple)

        options_box = QGroupBox()
        options_vbox = QVBoxLayout()
        options_box.setLayout(options_vbox)
        options_vbox.addWidget(usechange_cb)
        options_vbox.addWidget(multiple_cb)

        transaction_cache_size = wallet.get_cache_size_for_tx_bytedata()
        # nz_label = HelpLabel(_('Transaction Cache Size (MB)') + ':',
        #     _("This allows setting a per-wallet limit on the amount of transaction data cached "
        #     "in memory. A value of 0 will disable the cache, and setting low values can cause "
        #     "wallet slowness due to continual fetching of transaction data from the database."))
        nz_modifiable = app_state.config.is_modifiable('tx_bytedata_cache_size')
        nz = QSpinBox()
        nz.setAlignment(Qt.AlignRight)
        nz.setMinimum(MINIMUM_TXDATA_CACHE_SIZE_MB)
        nz.setMaximum(MAXIMUM_TXDATA_CACHE_SIZE_MB)
        nz.setValue(transaction_cache_size)
        nz.setEnabled(nz_modifiable)
        def on_nz():
            value = nz.value()
            # This will not resize the cache, as we do not want to be doing it with every
            # change and some changes may be bad to actually put in place.
            wallet.set_cache_size_for_tx_bytedata(value)
        nz.valueChanged.connect(on_nz)

        tx_cache_layout = QHBoxLayout()
        tx_cache_layout.setSpacing(15)
        tx_cache_layout.addWidget(nz)
        tx_cache_layout.addWidget(QLabel(_("MiB")))

        form = FormSectionWidget(minimum_label_width=120)
        form.add_row(_('Options'), options_box, True)
        form.add_row(_('Transaction Cache Size'), tx_cache_layout)

        vbox = QVBoxLayout()
        vbox.addWidget(form)
        vbox.addStretch(1)
        tab.setLayout(vbox)

    def account_widgets(self, account: AbstractAccount, tab: QWidget) -> None:
        label = QLabel(_("The settings below only affect the account '{}'")
                       .format(account.display_name()))

        script_type_combo = QComboBox()

        def update_script_types():
            default_script_type = account.get_default_script_type()
            combo_items = [ v.name for v in account.get_valid_script_types() ]

            script_type_combo.clear()
            script_type_combo.addItems(combo_items)
            script_type_combo.setCurrentIndex(script_type_combo.findText(default_script_type.name))

        def on_script_type_change(index):
            script_type_name = script_type_combo.currentText()
            new_script_type = getattr(ScriptType, script_type_name)
            current_script_type = account.get_default_script_type()
            if current_script_type == new_script_type:
                return
            account.set_default_script_type(new_script_type)
            self._main_window.update_receive_address_widget()

        if account.is_watching_only():
            script_type_combo.setEnabled(False)
        else:
            script_type_combo.currentIndexChanged.connect(on_script_type_change)

        update_script_types()

        form = FormSectionWidget(minimum_label_width=120)
        form.add_title(_("Account: {}").format(account.display_name()))
        form.add_row(_("Default script type"), script_type_combo)

        vbox = QVBoxLayout()
        vbox.addWidget(form)
        vbox.addStretch(1)
        tab.setLayout(vbox)

    def network_widgets(self, tab: QWidget) -> None:
        size_limit = app_state.electrumx_message_size_limit()
        nz_label = HelpLabel(_('Message size limit') + ':',
            _("This provides a denial of service limit for incoming messages. Messages that "
            "exceed this limit will be dropped. At this time our service connections work with "
            "JSON messages, so any included data will have been convered to text and will be at "
            "least twice the size. Make this at least double the size of the largest transaction "
            "you expect to receive.\n\nChanges only apply to new connections, not existing ones. "
            "For now you must restart ElectrumSV to be sure that any changes are applied."))
        nz_modifiable = app_state.config.is_modifiable('electrumx_message_size_limit')
        nz = QSpinBox()
        nz.setAlignment(Qt.AlignRight)
        nz.setMinimum(0)
        nz.setMaximum(MAXIMUM_TXDATA_CACHE_SIZE_MB) # This is a UI hard limit, not txdata..
        nz.setValue(size_limit)
        nz.setEnabled(nz_modifiable)
        def on_nz():
            value = nz.value()
            # This will not resize the cache, as we do not want to be doing it with every
            # change and some changes may be bad to actually put in place.
            app_state.set_electrumx_message_size_limit(value)
        nz.valueChanged.connect(on_nz)

        tx_cache_layout = QHBoxLayout()
        tx_cache_layout.setSpacing(15)
        tx_cache_layout.addWidget(nz)
        tx_cache_layout.addWidget(QLabel(_("MiB")))

        form = FormSectionWidget(minimum_label_width=120)
        form.add_row(nz_label, tx_cache_layout)
        # form.add_row(_('Message size limit'), tx_cache_layout)

        vbox = QVBoxLayout()
        vbox.addWidget(form)
        vbox.addStretch(1)
        tab.setLayout(vbox)
