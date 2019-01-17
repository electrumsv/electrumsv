from electrumsv.i18n import _

fullname = 'Ledger Wallet'
description = 'Provides support for Ledger hardware wallet'
requires = [('btchip', 'github.com/ledgerhq/btchip-python')]
registers_keystore = ('hardware', 'ledger', _("Ledger wallet"))
available_for = ['qt', 'cmdline']


def plugin(gui_kind):
    if gui_kind == 'qt':
        from . import qt as module
    elif gui_kind == 'cmdline':
        from . import cmdline as module
    else:
        raise ValueError(f'gui kind {gui_kind} not supported')
    return module.Plugin
