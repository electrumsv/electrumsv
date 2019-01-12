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


from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import (
    QTabWidget, QGridLayout, QLineEdit, QLabel, QComboBox, QVBoxLayout,
    QWidget, QSpinBox, QCheckBox, QDialog
)

from electrumsv.i18n import _, languages
import electrumsv.web as web
from electrumsv import paymentrequest, qrscanner

from .amountedit import BTCSatsByteEdit
from .util import ColorScheme, HelpLabel, Buttons, CloseButton


class PreferencesDialog(QDialog):

    # FIXME: most uses of parent in this file are wrong - changes should apply to ALL open
    # windows
    def __init__(self, parent):
        QDialog.__init__(self)
        self.parent = parent
        self.config = parent.config
        self.setWindowTitle(_('Preferences'))
        self.lay_out(parent)

    def closeEvent(self, event):
        self.parent.alias_received_signal.disconnect(self.set_alias_color)
        event.accept()

    def set_alias_color(self):
        if not self.config.get('alias'):
            self.alias_e.setStyleSheet("")
            return
        if self.parent.alias_info:
            _alias_addr, _alias_name, validated = self.parent.alias_info
            self.alias_e.setStyleSheet((ColorScheme.GREEN if validated
                                   else ColorScheme.RED).as_stylesheet(True))
        else:
            self.alias_e.setStyleSheet(ColorScheme.RED.as_stylesheet(True))

    def lay_out(self, parent):
        vbox = QVBoxLayout()
        tabs = QTabWidget()
        gui_widgets = []
        fee_widgets = []
        tx_widgets = []
        id_widgets = []

        # language
        lang_help = _('Select which language is used in the GUI (after restart).')
        lang_label = HelpLabel(_('Language') + ':', lang_help)
        lang_combo = QComboBox()

        language_names = []
        language_keys = []
        for item in languages.items():
            language_keys.append(item[0])
            language_names.append(item[1])
        lang_combo.addItems(language_names)
        try:
            index = language_keys.index(self.config.get("language",''))
        except ValueError:
            index = 0
        lang_combo.setCurrentIndex(index)

        if not self.config.is_modifiable('language'):
            for w in [lang_combo, lang_label]:
                w.setEnabled(False)

        def on_lang(_index):
            lang_request = language_keys[lang_combo.currentIndex()]
            if lang_request != self.config.get('language'):
                self.config.set_key("language", lang_request, True)
        lang_combo.currentIndexChanged.connect(on_lang)
        gui_widgets.append((lang_label, lang_combo))

        nz_help = _('Number of zeros displayed after the decimal point. '
                    'For example, if this is set to 2, "1." will be displayed as "1.00"')
        nz_label = HelpLabel(_('Zeros after decimal point') + ':', nz_help)
        nz = QSpinBox()
        nz.setMinimum(0)
        nz.setMaximum(parent.decimal_point)
        nz.setValue(parent.num_zeros)
        if not self.config.is_modifiable('num_zeros'):
            for w in [nz, nz_label]: w.setEnabled(False)
        def on_nz():
            value = nz.value()
            if parent.num_zeros != value:
                parent.num_zeros = value
                self.config.set_key('num_zeros', value, True)
                parent.history_list.update()
                parent.history_updated_signal.emit()
                parent.address_list.update()
        nz.valueChanged.connect(on_nz)
        gui_widgets.append((nz_label, nz))

        def on_customfee(_text):
            amt = customfee_e.get_amount()
            m = int(amt * 1000.0) if amt is not None else None
            self.config.set_key('customfee', m)
            parent.fee_slider.update()
            parent.fee_slider_mogrifier()

        customfee_e = BTCSatsByteEdit()
        customfee_e.setAmount(self.config.custom_fee_rate() / 1000.0
                              if self.config.has_custom_fee_rate() else None)
        customfee_e.textChanged.connect(on_customfee)
        customfee_label = HelpLabel(_('Custom Fee Rate'),
                                    _('Custom Fee Rate in Satoshis per byte'))
        fee_widgets.append((customfee_label, customfee_e))

        feebox_cb = QCheckBox(_('Edit fees manually'))
        feebox_cb.setChecked(self.config.get('show_fee', False))
        feebox_cb.setToolTip(_("Show fee edit box in send tab."))
        def on_feebox(state):
            self.config.set_key('show_fee', state == Qt.Checked)
            parent.fee_e.setVisible(state == Qt.Checked)
        feebox_cb.stateChanged.connect(on_feebox)
        fee_widgets.append((feebox_cb, None))

        msg = _('OpenAlias record, used to receive coins and to sign payment requests.') + '\n\n'\
              + _('The following alias providers are available:') + '\n'\
              + '\n'.join(['https://cryptoname.co/', 'http://xmr.link']) + '\n\n'\
              + 'For more information, see http://openalias.org'
        alias_label = HelpLabel(_('OpenAlias') + ':', msg)
        alias = self.config.get('alias','')
        self.alias_e = QLineEdit(alias)
        def on_alias_edit():
            self.alias_e.setStyleSheet("")
            alias = str(self.alias_e.text())
            self.config.set_key('alias', alias, True)
            if alias:
                self.parent.fetch_alias()
        self.set_alias_color()
        self.parent.alias_received_signal.connect(self.set_alias_color)
        self.alias_e.editingFinished.connect(on_alias_edit)
        id_widgets.append((alias_label, self.alias_e))

        # SSL certificate
        msg = ' '.join([
            _('SSL certificate used to sign payment requests.'),
            _('Use setconfig to set ssl_chain and ssl_privkey.'),
        ])
        if self.config.get('ssl_privkey') or self.config.get('ssl_chain'):
            try:
                SSL_identity = paymentrequest.check_ssl_config(self.config)
                SSL_error = None
            except BaseException as e:
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
        id_widgets.append((SSL_id_label, SSL_id_e))

        units = ['BSV', 'mBSV', 'bits']
        msg = _('Base unit of your wallet.')\
              + '\n1 BSV = 1,000 mBSV = 1,000,000 bits.\n' \
              + _(' These settings affect the fields in the Send tab')+' '
        unit_label = HelpLabel(_('Base unit') + ':', msg)
        unit_combo = QComboBox()
        unit_combo.addItems(units)
        unit_combo.setCurrentIndex(units.index(parent.base_unit()))
        def on_unit(_index):
            unit_result = units[unit_combo.currentIndex()]
            if parent.base_unit() == unit_result:
                return
            edits = parent.amount_e, parent.fee_e, parent.receive_amount_e
            amounts = [edit.get_amount() for edit in edits]
            if unit_result == 'BSV':
                parent.decimal_point = 8
            elif unit_result == 'mBSV':
                parent.decimal_point = 5
            elif unit_result == 'bits':
                parent.decimal_point = 2
            else:
                raise RuntimeError('Unknown base unit')
            self.config.set_key('decimal_point', parent.decimal_point, True)
            nz.setMaximum(parent.decimal_point)
            parent.history_list.update()
            parent.history_updated_signal.emit()
            parent.request_list.update()
            parent.address_list.update()
            for edit, amount in zip(edits, amounts):
                edit.setAmount(amount)
            parent.update_status()
        unit_combo.currentIndexChanged.connect(on_unit)
        gui_widgets.append((unit_label, unit_combo))

        block_explorers = web.BE_sorted_list()
        msg = _('Choose which online block explorer to use for functions that open a web browser')
        block_ex_label = HelpLabel(_('Online Block Explorer') + ':', msg)
        block_ex_combo = QComboBox()
        block_ex_combo.addItems(block_explorers)
        block_ex_combo.setCurrentIndex(block_ex_combo.findText(web.BE_from_config(self.config)))
        def on_be(_index):
            be_result = block_explorers[block_ex_combo.currentIndex()]
            self.config.set_key('block_explorer', be_result, True)
        block_ex_combo.currentIndexChanged.connect(on_be)
        gui_widgets.append((block_ex_label, block_ex_combo))

        system_cameras = qrscanner.find_system_cameras()
        qr_combo = QComboBox()
        qr_combo.addItem("Default","default")
        for camera, device in system_cameras.items():
            qr_combo.addItem(camera, device)
        #combo.addItem("Manually specify a device", config.get("video_device"))
        index = qr_combo.findData(self.config.get("video_device"))
        qr_combo.setCurrentIndex(index)
        msg = _("Install the zbar package to enable this.")
        qr_label = HelpLabel(_('Video Device') + ':', msg)
        qr_combo.setEnabled(qrscanner.libzbar is not None)
        def on_video_device(index):
            self.config.set_key("video_device", qr_combo.itemData(index), True)
        qr_combo.currentIndexChanged.connect(on_video_device)
        gui_widgets.append((qr_label, qr_combo))

        usechange_cb = QCheckBox(_('Use change addresses'))
        usechange_cb.setChecked(parent.wallet.use_change)
        if not self.config.is_modifiable('use_change'): usechange_cb.setEnabled(False)
        def on_usechange(state):
            usechange_result = state == Qt.Checked
            if parent.wallet.use_change != usechange_result:
                parent.wallet.use_change = usechange_result
                parent.wallet.storage.put('use_change', parent.wallet.use_change)
                multiple_cb.setEnabled(parent.wallet.use_change)
        usechange_cb.stateChanged.connect(on_usechange)
        usechange_cb.setToolTip(_('Using change addresses makes it more difficult for '
                                  'other people to track your transactions.'))
        tx_widgets.append((usechange_cb, None))

        def on_multiple(state):
            multiple = state == Qt.Checked
            if parent.wallet.multiple_change != multiple:
                parent.wallet.multiple_change = multiple
                parent.wallet.storage.put('multiple_change', multiple)
        multiple_change = parent.wallet.multiple_change
        multiple_cb = QCheckBox(_('Use multiple change addresses'))
        multiple_cb.setEnabled(parent.wallet.use_change)
        multiple_cb.setToolTip('\n'.join([
            _('In some cases, use up to 3 change addresses in order to break '
              'up large coin amounts and obfuscate the recipient address.'),
            _('This may result in higher transactions fees.')
        ]))
        multiple_cb.setChecked(multiple_change)
        multiple_cb.stateChanged.connect(on_multiple)
        tx_widgets.append((multiple_cb, None))

        def on_unconf(state):
            self.config.set_key('confirmed_only', state != Qt.Unchecked)
        conf_only = self.config.get('confirmed_only', False)
        unconf_cb = QCheckBox(_('Spend only confirmed coins'))
        unconf_cb.setToolTip(_('Spend only confirmed inputs.'))
        unconf_cb.setChecked(conf_only)
        unconf_cb.stateChanged.connect(on_unconf)
        tx_widgets.append((unconf_cb, None))

        # Fiat Currency
        hist_checkbox = QCheckBox()
        fiat_address_checkbox = QCheckBox()
        ccy_combo = QComboBox()
        ex_combo = QComboBox()

        enable_opreturn = bool(self.config.get('enable_opreturn'))
        opret_cb = QCheckBox(_('Enable OP_RETURN output'))
        opret_cb.setToolTip(_('Enable posting messages with OP_RETURN.'))
        opret_cb.setChecked(enable_opreturn)
        def on_op_return(checked_state):
            parent.on_op_return(checked_state != Qt.Unchecked)
        opret_cb.stateChanged.connect(on_op_return)
        tx_widgets.append((opret_cb, None))

        def update_currencies():
            if not parent.fx: return
            currencies = sorted(parent.fx.get_currencies(parent.fx.get_history_config()))
            ccy_combo.clear()
            ccy_combo.addItems([_('None')] + currencies)
            if parent.fx.is_enabled():
                ccy_combo.setCurrentIndex(ccy_combo.findText(parent.fx.get_currency()))

        def update_history_cb():
            if not parent.fx: return
            hist_checkbox.setChecked(parent.fx.get_history_config())
            hist_checkbox.setEnabled(parent.fx.is_enabled())

        def update_fiat_address_cb():
            if not parent.fx: return
            fiat_address_checkbox.setChecked(parent.fx.get_fiat_address_config())

        def update_exchanges():
            if not parent.fx: return
            b = parent.fx.is_enabled()
            ex_combo.setEnabled(b)
            if b:
                h = parent.fx.get_history_config()
                c = parent.fx.get_currency()
                exchanges = parent.fx.get_exchanges_by_ccy(c, h)
            else:
                exchanges = parent.fx.get_exchanges_by_ccy('USD', False)
            ex_combo.clear()
            ex_combo.addItems(sorted(exchanges))
            ex_combo.setCurrentIndex(ex_combo.findText(parent.fx.config_exchange()))

        def on_currency(index):
            if not parent.fx: return
            enabled = index != 0
            parent.fx.set_enabled(enabled)
            if enabled:
                parent.fx.set_currency(ccy_combo.currentText())
            update_history_cb()
            update_exchanges()
            parent.update_fiat()

        def on_exchange(_index):
            exchange = str(ex_combo.currentText())
            if (parent.fx and parent.fx.is_enabled() and
                    exchange and exchange != parent.fx.exchange.name()):
                parent.fx.set_exchange(exchange)

        def on_history(checked):
            if not parent.fx: return
            parent.fx.set_history_config(checked)
            update_exchanges()
            parent.history_list.refresh_headers()
            if parent.fx.is_enabled() and checked:
                # reset timeout to get historical rates
                parent.fx.timeout = 0

        def on_fiat_address(checked):
            if not parent.fx: return
            parent.fx.set_fiat_address_config(checked)
            parent.address_list.refresh_headers()
            parent.address_list.update()

        update_currencies()
        update_history_cb()
        update_fiat_address_cb()
        update_exchanges()
        ccy_combo.currentIndexChanged.connect(on_currency)
        hist_checkbox.stateChanged.connect(on_history)
        fiat_address_checkbox.stateChanged.connect(on_fiat_address)
        ex_combo.currentIndexChanged.connect(on_exchange)

        fiat_widgets = []
        fiat_widgets.append((QLabel(_('Fiat currency')), ccy_combo))
        fiat_widgets.append((QLabel(_('Show history rates')), hist_checkbox))
        fiat_widgets.append((QLabel(_('Show Fiat balance for addresses')), fiat_address_checkbox))
        fiat_widgets.append((QLabel(_('Source')), ex_combo))

        tabs_info = [
            (fee_widgets, _('Fees')),
            (tx_widgets, _('Transactions')),
            (gui_widgets, _('Appearance')),
            (fiat_widgets, _('Fiat')),
            (id_widgets, _('Identity')),
        ]
        for widgets, name in tabs_info:
            tab = QWidget()
            grid = QGridLayout(tab)
            grid.setColumnStretch(0,1)
            for a,b in widgets:
                i = grid.rowCount()
                if b:
                    if a:
                        grid.addWidget(a, i, 0)
                    grid.addWidget(b, i, 1)
                else:
                    grid.addWidget(a, i, 0, 1, 2)
            tabs.addTab(tab, name)

        vbox.addWidget(tabs)
        vbox.addStretch(1)
        vbox.addLayout(Buttons(CloseButton(self)))
        self.setLayout(vbox)
