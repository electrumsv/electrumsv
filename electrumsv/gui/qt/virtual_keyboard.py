# ElectrumSV - lightweight Bitcoin SV client
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

from collections import namedtuple
from functools import partial
import random

from PyQt5.QtWidgets import QGridLayout, QPushButton, QWidget

from electrumsv.i18n import _

from electrumsv.app_state import app_state
from .util import read_QIcon


VKBPage = namedtuple("VKBPage", "tooltip icon chars")
pages = [
    VKBPage(_('Lower-case letters'), 'text_lowercase.png', 'abcdefghijklmnopqrstuvwxyz_ '),
    VKBPage(_('Upper-case letters'), 'text_uppercase.png', 'ABCDEFGHIJKLMNOPQRTSUVWXYZ_ '),
    VKBPage(_('Numbers and symbols'), 'text_symbols.png',
            '1234567890!?.,;:/%&()[]{}+-=$#*@"\'\\<>~`'),
]
max_chars = max(len(page.chars) for page in pages)


def vkb_button(click_cb):
    button = QPushButton()
    button.clicked.connect(partial(click_cb, button))
    button.setFixedWidth(int(app_state.app.dpi / 3.6))
    return button


class VirtualKeyboard(QWidget):

    def __init__(self, pw_edit):
        super().__init__(pw_edit)
        self.pw_edit = pw_edit
        self.page = pages[0]
        # Our own shallow copy that we shuffle to get the on-screen order
        self.pages = pages.copy()
        self.refresh_button = vkb_button(self._refresh)
        self.refresh_button.setIcon(read_QIcon('refresh_win10_16.png'))
        self.refresh_button.setToolTip(_("Regenerate page"))
        self.page_buttons = [vkb_button(self._on_page_button) for page in pages]
        self.char_buttons = [vkb_button(self._char_pressed) for n in range(max_chars)]
        self.setLayout(self._create_grid_layout())
        self._refresh()

    def _refresh(self, _button=None):
        random.shuffle(self.pages)
        for button, page in zip(self.page_buttons, self.pages):
            button.setIcon(read_QIcon(page.icon))
            button.setToolTip(page.tooltip)
            button.setDisabled(page is self.page)
        self._shuffle_page()

    def _shuffle_page(self):
        chars = list(self.page.chars)
        random.shuffle(chars)
        for n, char_button in enumerate(self.char_buttons):
            if n < len(chars):
                char_button.setText(chars[n] if chars[n] != '&' else '&&')
                char_button.setVisible(True)
            else:
                char_button.setVisible(False)

    def _create_grid_layout(self):
        grid = QGridLayout()
        grid.setVerticalSpacing(2)
        grid.setHorizontalSpacing(1)
        grid.setContentsMargins(0, 4, 0, 0)

        rows = 6
        cols = (max_chars + rows - 1) // rows
        grid.addWidget(self.refresh_button, 0, cols + 1)
        for n, button in enumerate(self.page_buttons):
            grid.addWidget(button, n + 1, cols + 1)
        for n, button in enumerate(self.char_buttons):
            grid.addWidget(button, n // cols, n % cols)
        grid.setColumnMinimumWidth(cols, app_state.app.dpi / 12)
        return grid

    def _on_page_button(self, button):
        self.page = self.pages[self.page_buttons.index(button)]
        self._refresh()

    def _char_pressed(self, button):
        self.pw_edit.setText(self.pw_edit.text() + button.text()[0])
