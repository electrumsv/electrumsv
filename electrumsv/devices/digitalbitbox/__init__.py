from electrumsv.i18n import _

fullname = 'Digital Bitbox'
description = _('Provides support for Digital Bitbox hardware wallet')
registers_keystore = ('hardware', 'digitalbitbox', _("Digital Bitbox wallet"))
available_for = ['qt', 'cmdline']


def plugin(gui_kind):
    if gui_kind == 'qt':
        from . import qt as module
    elif gui_kind == 'cmdline':
        from . import cmdline as module
    else:
        raise ValueError(f'gui kind {gui_kind} not supported')
    return module.Plugin
