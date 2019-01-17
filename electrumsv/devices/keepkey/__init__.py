from electrumsv.i18n import _

fullname = 'KeepKey'
description = _('Provides support for KeepKey hardware wallet')
requires = [('keepkeylib','github.com/keepkey/python-keepkey')]
registers_keystore = ('hardware', 'keepkey', _("KeepKey wallet"))
available_for = ['qt', 'cmdline']


def plugin(gui_kind):
    if gui_kind == 'qt':
        from . import qt as module
    elif gui_kind == 'cmdline':
        from . import cmdline as module
    else:
        raise ValueError(f'gui kind {gui_kind} not supported')
    return module.Plugin
