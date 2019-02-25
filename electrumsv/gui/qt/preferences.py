# ElectrumSV - lightweight Bitcoin client
# Copyright (C) 2012 thomasv@gitorious
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

'''ElectrumSV Preferences dialog.'''

from functools import partial

from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import (
    QTabWidget, QGridLayout, QLineEdit, QLabel, QComboBox, QVBoxLayout,
    QWidget, QSpinBox, QCheckBox, QDialog, QGroupBox
)

from electrumsv import paymentrequest, qrscanner
from electrumsv.app_state import app_state
from electrumsv.extensions import label_sync
from electrumsv.extensions import extensions
from electrumsv.i18n import _, languages
import electrumsv.web as web

from .amountedit import BTCSatsByteEdit
from .util import (
    ColorScheme, HelpButton, HelpLabel, Buttons, CloseButton, MessageBox,
)


class PreferencesDialog(QDialog):

    def __init__(self, wallet=None):
        '''The preferences dialog has a wallet tab only if wallet is given.'''
        super().__init__()
        self.setWindowTitle(_('Preferences'))
        self.lay_out(wallet)
        self.initial_language = app_state.config.get('language', None)

    def accept(self):
        if app_state.fx:
            app_state.fx.timeout = 0
        # Qt on Mac has a bug with "modalSession has been exited prematurely" That means
        # you cannot create a modal dialog when exiting a model dialog, such as in the
        # finished signal.  So we do this in the accept() function instead.
        if self.initial_language != app_state.config.get('language', None):
            MessageBox.show_warning(
                _('Restart ElectrumSV to activate your updated language setting'),
                title=_('Success'), parent=self)
        super().accept()

    def lay_out(self, wallet):
        tabs_info = [
            (self.general_widgets(), _('General')),
            (self.tx_widgets(), _('Transactions')),
            (self.fiat_widgets(), _('Fiat')),
            (self.id_widgets(), _('Identity')),
            (self.extensions_widgets(wallet), _('Extensions')),
        ]
        if wallet:
            tabs_info.append((self.wallet_widgets(wallet), _('Wallet')))

        tabs = QTabWidget()
        tabs.setUsesScrollButtons(False)
        for widget_rows, name in tabs_info:
            tab = QWidget()
            grid = QGridLayout(tab)
            grid_width = max(len(widget_row) for widget_row in widget_rows)
            # Centre grid and push widgets left
            grid.setColumnStretch(grid_width, 1)

            def widgets(widget_row):
                prior_widget = None
                for col, widget in enumerate(widget_row):
                    if widget:
                        if prior_widget:
                            yield start_col, prior_widget, col - start_col
                        start_col = col
                        prior_widget = widget
                yield start_col, prior_widget, grid_width - start_col

            for row, widget_row in enumerate(widget_rows):
                for col, widget, col_span in widgets(widget_row):
                    grid.addWidget(widget, row, col, 1, col_span)
            grid.setRowStretch(row + 1, 1)
            tabs.addTab(tab, name)

        vbox = QVBoxLayout()
        vbox.addWidget(tabs)
        vbox.addStretch(1)
        vbox.addLayout(Buttons(CloseButton(self)))
        self.setLayout(vbox)

    def tx_widgets(self):
        def on_customfee(_text):
            amt = customfee_e.get_amount()
            m = int(amt * 1000.0) if amt is not None else None
            app_state.config.set_key('customfee', m)
            app_state.app.custom_fee_changed.emit()

        customfee_e = BTCSatsByteEdit()
        customfee_e.setAmount(app_state.config.custom_fee_rate() / 1000.0
                              if app_state.config.has_custom_fee_rate() else None)
        customfee_e.textChanged.connect(on_customfee)
        customfee_label = HelpLabel(_('Custom Fee Rate'),
                                    _('Custom Fee Rate in Satoshis per byte'))

        unconf_cb = QCheckBox(_('Spend only confirmed coins'))
        unconf_cb.setToolTip(_('Spend only confirmed inputs.'))
        unconf_cb.setChecked(app_state.config.get('confirmed_only', False))
        def on_unconf(state):
            app_state.config.set_key('confirmed_only', state != Qt.Unchecked)
        unconf_cb.stateChanged.connect(on_unconf)

        return [
            # Append None to flush edit left
            (customfee_label, customfee_e, None),
            (unconf_cb, ),
        ]

    def general_widgets(self):
        # language
        lang_modifiable = app_state.config.is_modifiable('language')
        lang_pairs = sorted((code, language) for language, code in languages.items())
        language_names, language_keys = zip(*lang_pairs)

        lang_label = HelpLabel(_('Language') + ':',
                               _('Select which language is used in the GUI (after restart).'))
        lang_label.setEnabled(lang_modifiable)

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
        nz_label = HelpLabel(_('Zeros after decimal point') + ':',
                             _('Number of zeros displayed after the decimal point.  '
                               'For example, if set to 2, "1." will be displayed as "1.00"'))
        nz_label.setEnabled(nz_modifiable)
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

        unit_label = HelpLabel(_('Base unit') + ':', '\n'.join((
            _('Base unit of display in the application.'),
            '1 BSV = 1,000 mBSV = 1,000,000 bits.',
        )))
        unit_combo = QComboBox()
        unit_combo.addItems(app_state.base_units)
        unit_combo.setCurrentIndex(app_state.base_units.index(app_state.base_unit()))
        def on_unit(index):
            app_state.set_base_unit(app_state.base_units[index])
            nz.setMaximum(app_state.decimal_point)
        unit_combo.currentIndexChanged.connect(on_unit)

        msg = _('Choose which online block explorer to use for functions that open a web browser')
        block_ex_label = HelpLabel(_('Online Block Explorer') + ':', msg)
        block_explorers = web.BE_sorted_list()
        block_ex_combo = QComboBox()
        block_ex_combo.addItems(block_explorers)
        block_ex_combo.setCurrentIndex(block_ex_combo.findText(
            web.BE_from_config(app_state.config)))
        def on_be(index):
            app_state.config.set_key('block_explorer', block_explorers[index], True)
        block_ex_combo.currentIndexChanged.connect(on_be)

        qr_label = HelpLabel(_('Video Device') + ':',
                             _("Install the zbar package to enable this."))
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

        updatecheck_box = QGroupBox(_("Software Updates"))
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

        return [
            (lang_label, lang_combo),
            (nz_label, nz),
            (unit_label, unit_combo),
            (block_ex_label, block_ex_combo),
            (qr_label, qr_combo),
            (updatecheck_box, ),
        ]

    def fiat_widgets(self):
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

        return [
            (QLabel(_('Fiat currency')), ccy_combo, QLabel(_('Source')), ex_combo),
            (hist_checkbox, ),
            (fiat_balance_checkbox, ),
        ]

    def id_widgets(self):
        msg = _('OpenAlias record, used to receive coins and to sign payment requests.') + '\n\n'\
              + _('The following alias providers are available:') + '\n'\
              + '\n'.join(['https://cryptoname.co/', 'http://xmr.link']) + '\n\n'\
              + 'For more information, see http://openalias.org'
        alias_label = HelpLabel(_('OpenAlias') + ':', msg)
        alias = app_state.config.get('alias','')
        alias_e = QLineEdit(alias)
        def on_alias_edit():
            alias_e.setStyleSheet("")
            app_state.set_alias(alias_e.text())
        def set_alias_color():
            if not app_state.config.get('alias'):
                alias_e.setStyleSheet("")
            elif app_state.alias_info:
                _alias_addr, _alias_name, validated = app_state.alias_info
                alias_e.setStyleSheet((ColorScheme.GREEN if validated
                                       else ColorScheme.RED).as_stylesheet(True))
            else:
                alias_e.setStyleSheet(ColorScheme.RED.as_stylesheet(True))
        app_state.app.alias_resolved.connect(set_alias_color)
        alias_e.editingFinished.connect(on_alias_edit)
        set_alias_color()

        # SSL certificate
        msg = ' '.join([
            _('SSL certificate used to sign payment requests.'),
            _('Use setconfig to set ssl_chain and ssl_privkey.'),
        ])
        if app_state.config.get('ssl_privkey') or app_state.config.get('ssl_chain'):
            try:
                SSL_identity = paymentrequest.check_ssl_config(app_state.config)
                SSL_error = None
            except Exception as e:
                SSL_identity = "error"
                SSL_error = str(e)
        else:
            SSL_identity = ""
            SSL_error = None
        SSL_id_label = HelpLabel(_('SSL certificate') + ':', msg)
        SSL_id_e = QLineEdit(SSL_identity)
        SSL_id_e.setStyleSheet((ColorScheme.RED if SSL_error else ColorScheme.GREEN)
                               .as_stylesheet(True) if SSL_identity else '')
        if SSL_error:
            SSL_id_e.setToolTip(SSL_error)
        SSL_id_e.setReadOnly(True)

        return [
            (alias_label, alias_e),
            (SSL_id_label, SSL_id_e),
        ]

    def extensions_widgets(self, wallet):
        def cb_clicked(extension, settings_widget, checked):
            extension.set_enabled(checked)
            if settings_widget:
                settings_widget.setEnabled(checked)

        widgets = []
        for extension in extensions:
            cb = QCheckBox(extension.name)
            cb.setChecked(extension.is_enabled())
            # Yes this is ugly
            if extension is label_sync and wallet:
                settings_widget = app_state.app.label_sync.settings_widget(self, wallet)
                settings_widget.setEnabled(extension.is_enabled())
            else:
                settings_widget = None
            cb.clicked.connect(partial(cb_clicked, extension, settings_widget))
            help_widget = HelpButton(extension.description)
            widgets.append((cb, settings_widget, help_widget))

        return widgets

    def wallet_widgets(self, wallet):
        label = QLabel(_("The settings below only affect the wallet {}")
                       .format(wallet.basename()))

        usechange_cb = QCheckBox(_('Use change addresses'))
        usechange_cb.setChecked(wallet.use_change)
        usechange_cb.setEnabled(app_state.config.is_modifiable('use_change'))
        usechange_cb.setToolTip(
            _('Using a different change address each time improves your privacy by '
              'making it more difficult for others to analyze your transactions.')
        )
        def on_usechange(state):
            usechange_result = state == Qt.Checked
            if wallet.use_change != usechange_result:
                wallet.use_change = usechange_result
                wallet.storage.put('use_change', wallet.use_change)
                multiple_cb.setEnabled(wallet.use_change)
        usechange_cb.stateChanged.connect(on_usechange)

        multiple_cb = QCheckBox(_('Use multiple change addresses'))
        multiple_cb.setChecked(wallet.multiple_change)
        multiple_cb.setEnabled(wallet.use_change)
        multiple_cb.setToolTip('\n'.join([
            _('In some cases, use up to 3 change addresses in order to break '
              'up large coin amounts and obfuscate the recipient address.'),
            _('This may result in higher transactions fees.')
        ]))
        def on_multiple(state):
            multiple = state == Qt.Checked
            if wallet.multiple_change != multiple:
                wallet.multiple_change = multiple
                wallet.storage.put('multiple_change', multiple)
        multiple_cb.stateChanged.connect(on_multiple)

        return [
            (label, ),
            (usechange_cb, ),
            (multiple_cb, ),
        ]
