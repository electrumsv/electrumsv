from electrumsv.i18n import _

fullname = 'TREZOR Wallet'
description = _('Provides support for TREZOR hardware wallet')
requires = [('trezorlib','github.com/trezor/python-trezor')]
registers_keystore = ('hardware', 'trezor', _("TREZOR wallet"))
available_for = ['qt', 'cmdline']


def plugin(gui_kind):
    if gui_kind == 'qt':
        from . import qt as module
    elif gui_kind == 'cmdline':
        from . import cmdline as module
    else:
        raise ValueError(f'gui kind {gui_kind} not supported')
    return module.Plugin
