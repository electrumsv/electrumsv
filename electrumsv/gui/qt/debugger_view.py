# Open BSV License version 4
#
# Copyright (c) 2021,2022 Bitcoin Association for BSV ("Bitcoin Association")
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# 1 - The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# 2 - The Software, and any software that is derived from the Software or parts thereof,
# can only be used on the Bitcoin SV blockchains. The Bitcoin SV blockchains are defined,
# for purposes of this license, as the Bitcoin blockchain containing block height #556767
# with the hash "000000000000000001d956714215d96ffc00e0afda4cd0a96c96f8d802b1662b" and
# that contains the longest persistent chain of blocks accepted by this Software and which
# are valid under the rules set forth in the Bitcoin white paper (S. Nakamoto, Bitcoin: A
# Peer-to-Peer Electronic Cash System, posted online October 2008) and the latest version
# of this Software available in this repository or another repository designated by Bitcoin
# Association, as well as the test blockchains that contain the longest persistent chains
# of blocks accepted by this Software and which are valid under the rules set forth in the
# Bitcoin whitepaper (S. Nakamoto, Bitcoin: A Peer-to-Peer Electronic Cash System, posted
# online October 2008) and the latest version of this Software available in this repository,
# or another repository designated by Bitcoin Association
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

# TODO The iterator is only used to pick out the script ranges for OP_CODESEPARATOR and this
#      works for executing transaction spends because we have the whole output script at hand.
#      For edited scripts there is no whole output script and we would need to generate it
#      on demand. Given that we have all the lines in memory, it should be possible to just
#      run back and find the code separator to sign relative to. Or more likely correct, run
#      forward to the signature point and find it (given conditionals).

# TODO Save and load scratchpad scripts, or a general workspace which might be either a
#      full transaction spend or scratchpad.

from __future__ import annotations
import dataclasses
from enum import IntEnum, IntFlag
from functools import partial
from typing import Any, cast, List, NamedTuple, Optional

from bitcoinx import classify_output_script, InterpreterLimits, MinerPolicy, minimal_push_opcode, \
    Ops, P2SH_Address, Script, TruncatedScriptError, Tx, TxInputContext, TxOutput

from PyQt5.QtCore import pyqtSignal, QAbstractItemModel, QModelIndex, QObject, QPoint, Qt
from PyQt5.QtGui import QBrush, QColor, QColorConstants, QFont, QKeyEvent
from PyQt5.QtWidgets import QAbstractItemView, QHBoxLayout, QHeaderView, QLabel, QMenu, \
    QPushButton, QStackedWidget, QTableView, QVBoxLayout, QWidget

from ...bitcoin import CustomInterpreterState, CustomLimitedStack, generate_matches, ScriptMatch
from ...i18n import _
from ...networks import Net
from ...platform import platform

from .table_widgets import ButtonLayout
from .util import read_QIcon


class ScriptControls(ButtonLayout):
    restart_signal = pyqtSignal()
    step_forward_signal = pyqtSignal()
    continue_signal = pyqtSignal()
    reset_signal = pyqtSignal()

    def __init__(self) -> None:
        super().__init__()

        self.addStretch(1)

        self._restart_button = self.add_button("icons8-skip-to-start-96-windows.png",
            self.restart_signal.emit, _("Reset to start"))

        self._step_forward_button = self.add_button("icons8-forward-96-windows.png",
            self.step_forward_signal.emit, _("Step forward"))
        self._step_forward_button.setShortcut(Qt.Key_F10)

        self._continue_button = self.add_button("icons8-play-96-windows.png",
            self.continue_signal.emit, _("Continue"))
        self._continue_button.setShortcut(Qt.Key_F5)

        self._reset_button = self.add_button("icons8-close-96-windows.png",
            self.reset_signal.emit, _("Clear"))

        self.addStretch(1)

        self._movement_enabled = True
        self.set_enabled(False)

    def set_enabled(self, is_enabled: bool=True) -> None:
        """
        Toggle all controls depending on whether the toolbar is enabled or not.
        """
        self._is_enabled = is_enabled

        self._restart_button.setEnabled(is_enabled)
        self._step_forward_button.setEnabled(is_enabled and self._movement_enabled)
        self._continue_button.setEnabled(is_enabled and self._movement_enabled)

    def set_movement_enabled(self, is_enabled: bool=True) -> None:
        """
        If execution is blocked then we disable the "movement" related controls.
        """
        self._movement_enabled = is_enabled
        if self._is_enabled:
            self._step_forward_button.setEnabled(is_enabled)
            self._continue_button.setEnabled(is_enabled)


PLACEHOLDER_TEXT = "<add an entry here>"

class Columns(IntEnum):
    ICON = 0
    LINE = 1
    TEXT = 2
    COLUMN_COUNT = 3


class LineFlags(IntFlag):
    NONE = 0

    IS_EDITABLE = 1 << 9
    IS_PLACEHOLDER = 1 << 10
    HAS_NUMBER = 1 << 11
    IS_LITERAL_VALUE = 1 << 12
    IS_TITLE = 1 << 13
    HAS_BREAKPOINT = 1 << 14
    HAS_ERROR = 1 << 15

    SECTION1 = 1 << 20
    SECTION2 = 1 << 21
    SECTION3 = 1 << 22
    SECTION_MASK = SECTION1 | SECTION2 | SECTION3


class RunStates(IntEnum):
    START = 0
    RUNNING = 1
    END = 2


@dataclasses.dataclass
class TableLine:
    text: str
    flags: LineFlags
    number: int = -1
    match: Optional[ScriptMatch] = dataclasses.field(default=None)


class TableModel(QAbstractItemModel):
    def __init__(self, parent: TableView, column_count: int, first_line_number: int) -> None:
        super().__init__(parent)

        self._view = parent
        self._column_count = column_count
        self._first_line_number = first_line_number
        # self._logger = self._view._logger

        self._marker_icon = read_QIcon("icons8-play-96-windows.png")
        self._breakpoint_icon = read_QIcon("icons8-pause-button-96-material-red.png")

    def _can_edit_line(self, line: TableLine) -> bool:
        return self._view._widget.editing_enabled and line.flags & LineFlags.IS_EDITABLE != 0

    def get_line(self, row_index: int) -> TableLine:
        if row_index < 0:
            row_index = len(self._data) + row_index
        return self._data[row_index]

    def set_data(self, data: List[TableLine]) -> None:
        # The initial line numbers need to be set correctly. An edit of a given line relies on the
        # preceding line numbers being correct.
        line_number = self._first_line_number
        for line in data:
            if line.flags & LineFlags.HAS_NUMBER:
                line.number = line_number
                line_number += 1

        self.beginResetModel()
        self._data = data
        self.endResetModel()

    def append_line(self, line: TableLine) -> None:
        # The `_append_line` will signal it's line insertion.
        insert_row = self._append_line(line)

        # If there are any other rows that need to be updated relating to the data in that
        # line, here is the place to do it.  Then signal what has changed.

    def _append_line(self, line: TableLine) -> int:
        insert_row = len(self._data)
        if line.flags & LineFlags.HAS_NUMBER:
            line.number = self._get_current_line_number(insert_row)

        # Signal the insertion of the new row.
        self.beginInsertRows(QModelIndex(), insert_row, insert_row)
        row_count = self.rowCount(QModelIndex())
        if insert_row == row_count:
            self._data.append(line)
        else:
            # Insert the data entries.
            self._data.insert(insert_row, line)
        self.endInsertRows()

        return insert_row

    def remove_row(self, row_index: int) -> TableLine:
        if row_index < 0:
            row_index = len(self._data) + row_index
        line = self._data[row_index]

        self.beginRemoveRows(QModelIndex(), row_index, row_index)
        del self._data[row_index]
        self.endRemoveRows()

        return line

    def invalidate_column(self, column_index: int) -> None:
        start_index = self.createIndex(0, column_index)
        row_count = self.rowCount(start_index)
        end_index = self.createIndex(row_count-1, column_index)
        self.dataChanged.emit(start_index, end_index)

    def invalidate_row(self, row_index: int) -> None:
        if row_index < 0:
            row_index = len(self._data) + row_index
        start_index = self.createIndex(row_index, 0)
        column_count = self.columnCount(start_index)
        end_index = self.createIndex(row_index, column_count-1)
        self.dataChanged.emit(start_index, end_index)

    # Overridden methods:

    def columnCount(self, model_index: QModelIndex=QModelIndex()) -> int:
        return self._column_count

    def data(self, model_index: QModelIndex, role: int=Qt.ItemDataRole.DisplayRole) -> Any:
        row = model_index.row()
        column = model_index.column()
        if row >= len(self._data):
            return None
        if column >= self._column_count:
            return None

        if model_index.isValid():
            line = self._data[row]

            if role == Qt.ItemDataRole.DecorationRole:
                if column == Columns.ICON:
                    if row == self._view._widget.current_row:
                        return self._marker_icon
                    elif line.flags & LineFlags.HAS_BREAKPOINT:
                        return self._breakpoint_icon

            elif role == Qt.ItemDataRole.DisplayRole:
                if column == Columns.LINE:
                    if line.number != -1:
                        return str(line.number)
                elif column == Columns.TEXT:
                    if line.flags & LineFlags.IS_PLACEHOLDER:
                        return PLACEHOLDER_TEXT
                    return line.text
            elif role == Qt.ItemDataRole.FontRole:
                if line.flags & LineFlags.IS_LITERAL_VALUE:
                    return self._view._monospace_font

            elif role == Qt.ItemDataRole.ForegroundRole:
                if line.flags & LineFlags.IS_TITLE:
                    return self._view._title_fg_brush

            elif role == Qt.ItemDataRole.BackgroundRole:
                if line.flags & LineFlags.IS_TITLE:
                    return self._view._title_bg_brush
                elif line.flags & LineFlags.HAS_ERROR:
                    return self._view._error_bg_brush
                elif row == self._view._widget.current_row:
                    return self._view._active_bg_brush

            elif role == Qt.ItemDataRole.TextAlignmentRole:
                if column == Columns.TEXT:
                    if line.flags & (LineFlags.IS_TITLE | LineFlags.IS_PLACEHOLDER) == 0:
                        return Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter
                return Qt.AlignmentFlag.AlignCenter

            elif role == Qt.ItemDataRole.ToolTipRole:
                return "No tooltips yet"

            elif role == Qt.ItemDataRole.EditRole:
                if column == Columns.TEXT and self._can_edit_line(line):
                    return line.text

    def flags(self, model_index: QModelIndex) -> Qt.ItemFlags:
        if model_index.isValid():
            row = model_index.row()
            column = model_index.column()
            item_flags = super().flags(model_index)
            line = self._data[row]
            if column == Columns.TEXT and self._can_edit_line(line):
                item_flags = Qt.ItemFlags( # type: ignore[call-overload]
                    int(item_flags) | Qt.ItemFlag.ItemIsEditable)
            return item_flags
        return Qt.ItemFlags(Qt.ItemFlag.ItemIsEnabled)

    def index(self, row_index: int, column_index: int,
            parent: QModelIndex=QModelIndex()) -> QModelIndex:
        if self.hasIndex(row_index, column_index, parent):
            return self.createIndex(row_index, column_index)
        return QModelIndex()

    # NOTE(typing) I have no idea what this wants in the way of typing. The errors do not help.
    def parent(self, index: QModelIndex) -> QModelIndex: # type: ignore[override]
        return QModelIndex()

    def rowCount(self, model_index: QModelIndex=QModelIndex()) -> int:
        return len(self._data)

    def setData(self, model_index: QModelIndex, value: Any,
            role: int=Qt.ItemDataRole.EditRole) -> bool:
        if model_index.isValid() and role == Qt.ItemDataRole.EditRole:
            row = model_index.row()
            existing_line = self._data[row]
            if model_index.column() == Columns.TEXT:
                text = cast(Optional[str], value)
                text = "" if text is None else text.strip()

                updated_line = dataclasses.replace(existing_line, text=text)
                if text == "":
                    updated_line.flags |= LineFlags.IS_PLACEHOLDER
                    updated_line.flags &= ~LineFlags.HAS_NUMBER
                    updated_line.number = -1
                else:
                    updated_line.flags &= ~LineFlags.IS_PLACEHOLDER
                    updated_line.flags |= LineFlags.HAS_NUMBER

                if not self._view._widget.process_line_edit(row, existing_line, updated_line):
                    return False

                # Force the edited cell for the given line to update.
                self._data[row] = updated_line
                self.dataChanged.emit(model_index, model_index)

                # Update the line number on the current line.
                next_line_number = existing_line.number
                if updated_line.flags & LineFlags.HAS_NUMBER:
                    updated_line.number = self._get_current_line_number(row)
                    next_line_number = updated_line.number + 1

                    if row == len(self._data)-1:
                        self.append_line(TableLine("",
                            LineFlags.IS_PLACEHOLDER | LineFlags.IS_EDITABLE |
                                (updated_line.flags & LineFlags.SECTION_MASK)))

                # Update the line numbers on any following line.
                line_index = row + 1
                while line_index < len(self._data):
                    following_line = self._data[line_index]
                    if following_line.flags & LineFlags.HAS_NUMBER:
                        following_line.number = next_line_number
                        next_line_number += 1
                    line_index += 1

                self.invalidate_column(Columns.LINE)
                return True
        return False

    def _get_current_line_number(self, row: int) -> int:
        # This assumes that all the preceding line numbers are correct.
        # If the model is populated with lines, they should get line numbers set then.
        focus_row = row
        while focus_row > -1:
            if focus_row != len(self._data):
                line = self._data[focus_row]
                if line.flags & LineFlags.HAS_NUMBER:
                    if row == focus_row:
                        if line.number != -1:
                            return line.number
                    else:
                        return line.number + 1
            focus_row -= 1

        return self._first_line_number

    def get_next_row(self, start_row: int, mask: LineFlags) -> int:
        current_row = start_row + 1
        while current_row < len(self._data):
            line = self._data[current_row]
            if line.flags & mask:
                return current_row
            current_row += 1
        return -1


class TableView(QTableView):
    def __init__(self, table_widget: BaseTableWidget, lines: List[TableLine],
            first_line_number: int) -> None:
        super().__init__()

        self._widget = table_widget
        self._monospace_font = QFont(platform.monospace_font)
        self._title_fg_brush = QBrush(QColor(QColorConstants.White))
        self._title_bg_brush = QBrush(QColor.fromRgb(0x57, 0x84, 0xBA))
        self._active_bg_brush = QBrush(QColor.fromRgb(0xB6, 0xD8, 0xF2))
        self._error_bg_brush = QBrush(QColor.fromRgb(0xC5, 0xB4, 0x6C))

        self.setVerticalScrollMode(QAbstractItemView.ScrollPerPixel)
        self.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)

        self.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)

        self._model = TableModel(self, Columns.COLUMN_COUNT, first_line_number)
        self._model.set_data(lines)
        self.setModel(self._model)

        horizontalHeader = self.horizontalHeader()
        horizontalHeader.setVisible(False)
        horizontalHeader.setMinimumSectionSize(20)
        horizontalHeader.setSectionResizeMode(Columns.ICON, QHeaderView.ResizeToContents)
        horizontalHeader.setSectionResizeMode(Columns.LINE, QHeaderView.ResizeToContents)
        horizontalHeader.setSectionResizeMode(Columns.TEXT, QHeaderView.Stretch)
        self.verticalHeader().setVisible(False)

    def get_line(self, row_index: int) -> TableLine:
        return self._model.get_line(row_index)

    def refresh_row(self, row_index: int) -> None:
        self._model.invalidate_row(row_index)

    def set_lines(self, lines: List[TableLine]) -> None:
        self._model.set_data(lines)

    def append_lines(self, lines: List[TableLine]) -> None:
        for line in lines:
            self._model.append_line(line)


class BaseTableWidget(QWidget):
    current_row = -1
    editing_enabled = True

    def __init__(self, lines: List[TableLine], first_line_number: int) -> None:
        super().__init__()

        self._table_view = TableView(self, lines, first_line_number)

        self._vbox = vbox = QVBoxLayout()
        vbox.setSpacing(0)
        vbox.setContentsMargins(0, 0, 0, 0)
        vbox.addWidget(self._table_view)
        self.setLayout(vbox)

    def set_lines(self, lines: List[TableLine]) -> None:
        self._table_view.set_lines(lines)

    def append_lines(self, lines: List[TableLine]) -> None:
        self._table_view.append_lines(lines)


def create_default_script_evaluation_limits() -> InterpreterLimits:
    is_genesis_enabled = True
    is_transaction_in_block = False
    miner_policy = MinerPolicy(100_000, 64, 20_000, 1_000, 16)
    return InterpreterLimits(miner_policy, is_genesis_enabled,
        is_transaction_in_block)


class UILimitedStack(CustomLimitedStack, QObject):
    """
    Override all stack operations with signals to prompt keeping the UI synchronised.
    """
    append_signal = pyqtSignal(object)
    replace_signal = pyqtSignal(object, int)
    pop_signal = pyqtSignal(object, int)
    refresh_signal = pyqtSignal(object)

    def __init__(self, size_limit: int) -> None:
        CustomLimitedStack.__init__(self, size_limit)
        QObject.__init__(self)

    # Covers `extend` as well.
    def append(self, item: Any) -> None:
        super().append(item)
        self.append_signal.emit(item)

    def __setitem__(self, key: int, item: Any) -> None:
        super().__setitem__(key, item)
        self.replace_signal.emit(item, key)

    def pop(self, index: int=-1) -> Any:
        item = super().pop(index)
        self.pop_signal.emit(item, index)
        return item

    def restore_copy(self, stack: UILimitedStack) -> None:
        super().restore_copy(stack)
        self.refresh_signal.emit(stack._items)


class UIInterpreterState(CustomInterpreterState):
    stack: UILimitedStack
    alt_stack: UILimitedStack

    STACK_CLS = UILimitedStack


class ScriptView(BaseTableWidget):
    FIRST_LINE_NUMBER = 1

    block_state_change_signal = pyqtSignal(bool)

    def __init__(self, lines: List[TableLine]) -> None:
        super().__init__(lines, self.FIRST_LINE_NUMBER)

        self._section_scripts: List[Script] = []
        self._active_section = LineFlags.NONE
        self._active_script: Optional[Script] = None

        title_label = QLabel(_("Scripts"))
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._vbox.insertWidget(0, title_label)

        self.toolbar = ScriptControls()
        self._vbox.insertLayout(1, self.toolbar)

        self._table_view.clicked.connect(self._event_clicked)
        self._table_view.customContextMenuRequested.connect(
            self._event_custom_context_menu_requested)

    def set_enable_edit(self, flag: bool) -> None:
        self.editing_enabled = flag

    def setup_standalone_script(self, script: Optional[Script]) -> None:
        lines: List[TableLine] = []
        lines.append(TableLine(_("Script scratchpad"), LineFlags.IS_TITLE | LineFlags.SECTION1))

        if script is not None:
            self._extend_lines_from_script(lines, script, LineFlags.SECTION1)
        else:
            lines.append(TableLine("", LineFlags.IS_PLACEHOLDER | LineFlags.IS_EDITABLE |
                LineFlags.SECTION1))

        self._table_view.set_lines(lines)

        # TODO(empty-script) There's something to be done here to update this if the user edits.
        if script is None:
            script = Script()
        self._section_scripts = [ script ]

        self._reset_script_state()

    def setup_transaction_spend(self, context: Optional[TransactionSpendContext]) -> None:
        unlocking_script: Optional[Script] = None
        locking_script: Optional[Script] = None
        spent_output: Optional[TxOutput] = None

        if context is not None:
            child_input = context.child_transaction.inputs[context.child_input_index]
            unlocking_script = child_input.script_sig
            spent_output = context.parent_transaction.outputs[child_input.prev_idx]
            locking_script = spent_output.script_pubkey

        self._section_scripts = []

        lines: List[TableLine] = []
        lines.append(TableLine(_("Unlocking script"), LineFlags.IS_TITLE | LineFlags.SECTION1))
        if unlocking_script is not None:
            self._extend_lines_from_script(lines, unlocking_script, LineFlags.SECTION1)
            self._section_scripts.append(unlocking_script)
        else:
            lines.append(TableLine("", LineFlags.IS_PLACEHOLDER | LineFlags.SECTION1))
            # TODO(empty-script) There's something to be done here to update this if the user edits.
            self._section_scripts.append(Script())

        lines.append(TableLine(_("Locking script"), LineFlags.IS_TITLE | LineFlags.SECTION2))
        if locking_script is not None:
            self._extend_lines_from_script(lines, locking_script, LineFlags.SECTION2)
            self._section_scripts.append(locking_script)
        else:
            lines.append(TableLine("", LineFlags.IS_PLACEHOLDER | LineFlags.SECTION2))
            # TODO(empty-script) There's something to be done here to update this if the user edits.
            self._section_scripts.append(Script())

        # TODO(untested) This needs to be tested with a P2SH transaction.
        if locking_script is not None and unlocking_script is not None:
            if isinstance(classify_output_script(locking_script, Net.COIN), P2SH_Address):
                lines.append(TableLine(_("Locking script (P2SH)"),
                    LineFlags.IS_TITLE | LineFlags.SECTION3))
                p2sh_locking_script = self._get_p2sh_script_from_script(unlocking_script)
                self._extend_lines_from_script(lines, p2sh_locking_script, LineFlags.SECTION3)

        self._table_view.set_lines(lines)

        input_context: Optional[TxInputContext] = None
        if context is not None:
            is_utxo_after_genesis = True
            input_context = TxInputContext(context.child_transaction, context.child_input_index,
                spent_output, is_utxo_after_genesis)
        self._reset_script_state(input_context)

    def get_interpreter(self) -> UIInterpreterState:
        assert self._interpreter is not None
        return self._interpreter

    def _get_p2sh_script_from_script(self, script: Script) -> Script:
        lines: List[TableLine] = []
        self._extend_lines_from_script(lines, script, LineFlags.NONE)
        match = lines[-1].match
        assert match is not None and match.data is not None
        return Script(match.data)

    def _extend_lines_from_script(self, lines: List[TableLine], script: Script,
            flags: LineFlags) -> None:
        try:
            for match in generate_matches(bytes(script)):
                value = match.data
                text = "UNEXPECTED ERROR"
                if value is None:
                    text = Script.op_to_asm_word(match.op, False)
                elif isinstance(value, bytes):
                    text = value[:16].hex()
                    if len(value) > 4:
                        text += "..."
                lines.append(TableLine(text, LineFlags.HAS_NUMBER | LineFlags.IS_EDITABLE | flags,
                    match=match))
        except TruncatedScriptError:
            pass

    def _reset_script_state(self, input_context: Optional[TxInputContext]=None) -> None:
        limits = create_default_script_evaluation_limits()
        self._interpreter = UIInterpreterState(limits, input_context)

        next_row = self._table_view._model.get_next_row(-1,
            LineFlags.HAS_NUMBER | LineFlags.IS_PLACEHOLDER)
        if next_row != -1:
            self.current_row = next_row
            self._table_view._model.invalidate_row(self.current_row)

            self.block_state_change_signal.emit(self.is_blocked())
        else:
            self.current_row = -1

    def step_script_evaluation(self) -> bool:
        """
        This is used by both the running and stepping mechanisms.

        A placeholder row will block further stepping.
        A
        """
        current_row = self.current_row
        current_line = self._table_view.get_line(current_row)
        next_row = self._table_view._model.get_next_row(current_row,
            LineFlags.HAS_NUMBER | LineFlags.IS_PLACEHOLDER)
        current_section = current_line.flags & LineFlags.SECTION_MASK
        assert current_section

        if current_line.flags & LineFlags.IS_PLACEHOLDER:
            self.block_state_change_signal.emit(True)
            return True

        if current_section != self._active_section:
            current_script = self.get_script_for_line(current_line)

            if self._active_script is None:
                self._active_script = current_script
                self._active_section = current_section

                self._interpreter.begin_evaluate_script(current_script)
            else:
                assert self._active_script == current_script

        evaluation_incomplete = True
        if current_line.flags & LineFlags.HAS_NUMBER:
            assert current_line.match is not None
            try:
                evaluation_incomplete = self._interpreter.step_evaluate_script(current_line.match)
            except Exception:
                current_line.flags |= LineFlags.HAS_ERROR
                self._table_view.refresh_row(current_row)
                raise

        self._table_view.refresh_row(current_row)
        self.current_row = next_row

        if next_row == -1:
            evaluation_incomplete = False
            end_of_section = True
        else:
            next_line = self._table_view.get_line(next_row)
            next_section = next_line.flags & LineFlags.SECTION_MASK
            end_of_section = next_section != self._active_section
            self._table_view.refresh_row(next_row)

            if next_line.flags & LineFlags.IS_PLACEHOLDER:
                self.block_state_change_signal.emit(True)

        if not evaluation_incomplete or end_of_section:
            self._active_script = None
            self._active_section = LineFlags.NONE

            self._interpreter.end_evaluate_script()

        return evaluation_incomplete

    def at_breakpoint(self) -> bool:
        if self.current_row == -1:
            return False
        current_line = self._table_view.get_line(self.current_row)
        return current_line.flags & LineFlags.HAS_BREAKPOINT != 0

    def is_blocked(self) -> bool:
        if self.current_row == -1:
            return False
        current_line = self._table_view.get_line(self.current_row)
        return current_line.flags & LineFlags.IS_PLACEHOLDER != 0

    def get_script_for_line(self, line: TableLine) -> Script:
        if line.flags & LineFlags.SECTION1:
            return self._section_scripts[0]
        elif line.flags & LineFlags.SECTION2:
            return self._section_scripts[1]
        elif line.flags & LineFlags.SECTION3:
            return self._section_scripts[2]
        raise NotImplementedError(f"line has not detectable section {line}")

    def _event_custom_context_menu_requested(self, position: QPoint) -> None:
        menu_index = self._table_view.indexAt(position)
        row = menu_index.row()

        menu = QMenu()

        current_line = self._table_view.get_line(self.current_row)
        add_separator = False
        if current_line.flags & LineFlags.IS_EDITABLE:
            menu.addAction(_("Edit"), partial(self._toggle_breakpoint, row))
            add_separator = True
        if current_line.flags & LineFlags.HAS_NUMBER:
            if add_separator:
                menu.addSeparator()
            menu.addAction(_("Toggle breakpoint"), partial(self._toggle_breakpoint, row))

        menu.exec_(self._table_view.viewport().mapToGlobal(position))

    def _event_clicked(self, index: QModelIndex) -> None:
        row = index.row()
        column = index.column()
        if column == Columns.ICON:
            self._toggle_breakpoint(row)

    def keyPressEvent(self, event: QKeyEvent) -> None:
        if event.key() == Qt.Key_F9:
            index = self._table_view.currentIndex()
            self._toggle_breakpoint(index.row())
        else:
            super().keyPressEvent(event)

    def _toggle_breakpoint(self, row: int) -> None:
        line = self._table_view.get_line(row)
        if line.flags & LineFlags.HAS_NUMBER:
            line.flags ^= LineFlags.HAS_BREAKPOINT
            self._table_view.refresh_row(row)

    def process_line_edit(self, row: int, old_line: TableLine, new_line: TableLine) -> bool:
        if new_line.flags & LineFlags.HAS_NUMBER:
            text_value = new_line.text
            upper_text = text_value.upper()
            if upper_text.startswith("OP_"):
                op = getattr(Ops, upper_text, None)
                if op is None:
                    # This should likely happen in the edit dialog submit.
                    return False
                new_line.match = ScriptMatch(op, None, None, None, 0)
            else:
                first_character = text_value[0]
                last_character = text_value[-1]
                if first_character in { "\"", "'" } and first_character == last_character:
                    bytes_value = text_value[1:-1].encode()
                elif text_value.startswith("$") or text_value.startswith("0x"):
                    text_value = text_value[2:] if first_character == "0" else text_value[1:]
                    try:
                        bytes_value = bytes.fromhex(text_value)
                    except ValueError:
                        return False
                else:
                    try:
                        int_value = int(text_value)
                    except ValueError:
                        return False
                    else:
                        bytes_value = int_value.to_bytes((int_value.bit_count() + 7) // 8, 'little')

                op = minimal_push_opcode(bytes_value)
                new_line.match = ScriptMatch(op, bytes_value, None, None, 0)

        is_block_state_change = row == self.current_row and \
            ((old_line.flags & LineFlags.IS_PLACEHOLDER) +
                (new_line.flags & LineFlags.IS_PLACEHOLDER)) == LineFlags.IS_PLACEHOLDER

        if is_block_state_change:
            self.block_state_change_signal.emit(
                (new_line.flags & LineFlags.IS_PLACEHOLDER) == LineFlags.IS_PLACEHOLDER)

        return True


class StackView(BaseTableWidget):
    FIRST_LINE_NUMBER = 0

    def __init__(self, title: str, lines: List[TableLine]) -> None:
        super().__init__(lines, self.FIRST_LINE_NUMBER)

        title_label = QLabel(title)
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._vbox.insertWidget(0, title_label)

    def bind_stack(self, stack: UILimitedStack) -> None:
        stack.append_signal.connect(self._on_stack_append)
        stack.replace_signal.connect(self._on_stack_replace)
        stack.pop_signal.connect(self._on_stack_pop)
        stack.refresh_signal.connect(self._on_stack_refresh)

        self._on_stack_refresh(stack._items)

    def reset(self) -> None:
        self._table_view.set_lines([])

    def _item_repr(self, item: bytes) -> str:
        text = item[:16].hex()
        if len(item) > 4:
            text += "..."
        return text

    def _on_stack_append(self, item: Any) -> None:
        text = self._item_repr(item)
        line = TableLine(text, LineFlags.HAS_NUMBER)
        self.append_lines([ line ])

    def _on_stack_replace(self, new_item: Any, index: int) -> None:
        assert index < 0
        line = self._table_view.get_line(index)
        line.text = self._item_repr(new_item)
        self._table_view.refresh_row(index)

    def _on_stack_pop(self, expected_item: Any, index: int) -> None:
        # Remove the item at the index, which should be the expected item value.
        # The index should be a negative offset.
        # Convert index to row.
        assert index < 0
        self._table_view._model.remove_row(index)

    def _on_stack_refresh(self, items: List[bytes]) -> None:
        lines: List[TableLine] = []
        for item in items:
            text = self._item_repr(item)
            lines.append(TableLine(text, LineFlags.HAS_NUMBER))
        self._table_view.set_lines(lines)


class DebugTemplateKind(IntEnum):
    SCRIPT_SCRATCHPAD = 1
    TRANSACTION_SPEND = 2


class DebugSetupView(QWidget):
    setup_template_signal = pyqtSignal(DebugTemplateKind)

    def __init__(self) -> None:
        super().__init__()

        hbox = QHBoxLayout()
        vbox = QVBoxLayout()

        label = QLabel(_("Choose a debugging template:"))
        scratch_button = QPushButton(_("Script scratchpad"))
        scratch_button.clicked.connect(
            partial(self.setup_template_signal.emit, DebugTemplateKind.SCRIPT_SCRATCHPAD))
        tx_spend_button = QPushButton(_("Transaction spend"))
        tx_spend_button.clicked.connect(
            partial(self.setup_template_signal.emit, DebugTemplateKind.TRANSACTION_SPEND))

        vbox.addStretch(1)
        vbox.addWidget(label)
        vbox.addWidget(scratch_button)
        vbox.addWidget(tx_spend_button)
        vbox.addStretch(1)

        hbox.addStretch(1)
        hbox.addLayout(vbox)
        hbox.addStretch(1)

        self.setLayout(hbox)


class TransactionSpendContext(NamedTuple):
    parent_transaction: Tx
    child_transaction: Tx
    child_input_index: int


class DebuggerView(QWidget):
    def __init__(self) -> None:
        super().__init__()

        self._state_ui_enabled = False
        self._state_movement_ui_enabled = False

        self.setLayout(self.create_layout())

        self._script_view.block_state_change_signal.connect(self._event_debugging_movement_blocked)

    def create_layout(self) -> QVBoxLayout:
        self._setup_view = DebugSetupView()
        self._setup_view.setup_template_signal.connect(self._on_setup_template_choice)

        self._stacked_widget = QStackedWidget()
        self._stacked_widget.addWidget(self._setup_view)

        self._create_script_view()

        self._main_stack_view = StackView(_("Main stack"), [])
        self._alt_stack_view = StackView(_("Alt stack"), [])

        vbox = QVBoxLayout()
        vbox.setSpacing(0)
        vbox.setContentsMargins(0, 4, 0, 4)
        hbox = QHBoxLayout()
        hbox.setSpacing(4)
        hbox.setContentsMargins(0, 0, 4, 0)
        hbox.addWidget(self._stacked_widget)
        hbox.addWidget(self._main_stack_view)
        hbox.addWidget(self._alt_stack_view)
        vbox.addLayout(hbox, 1)
        return vbox

    def _create_script_view(self) -> None:
        self._script_view = ScriptView([])
        self._script_view.toolbar.step_forward_signal.connect(self._event_step_script)
        self._script_view.toolbar.continue_signal.connect(self._event_run_script)
        self._script_view.toolbar.reset_signal.connect(self._event_clear_script)

        self._stacked_widget.addWidget(self._script_view)

    def _reset_script_view(self) -> None:
        was_current_widget = self._stacked_widget.currentWidget() is self._script_view
        self._stacked_widget.removeWidget(self._script_view)
        self._create_script_view()
        if was_current_widget:
            self._stacked_widget.setCurrentWidget(self._script_view)

    def set_scratch_mode(self, script: Optional[Script]=None) -> None:
        self._stacked_widget.setCurrentWidget(self._script_view)
        self._script_view.setup_standalone_script(script)

        interpreter = self._script_view.get_interpreter()
        self._main_stack_view.bind_stack(interpreter.stack)
        self._alt_stack_view.bind_stack(interpreter.alt_stack)

        self.set_debugging_toolbar_enabled(True)

    def set_transaction_spend_mode(self, context: Optional[TransactionSpendContext]=None) -> None:
        self._stacked_widget.setCurrentWidget(self._script_view)
        self._script_view.setup_transaction_spend(context)

        interpreter = self._script_view.get_interpreter()
        self._main_stack_view.bind_stack(interpreter.stack)
        self._alt_stack_view.bind_stack(interpreter.alt_stack)

        self.set_debugging_toolbar_enabled(True)

    def set_debugging_toolbar_enabled(self, is_enabled: bool=True) -> None:
        self._state_ui_enabled = is_enabled
        self._script_view.toolbar.set_enabled(is_enabled)
        if is_enabled:
            self.set_debugging_movement_enabled(not self._script_view.is_blocked())

    def set_debugging_movement_enabled(self, is_enabled: bool=True) -> None:
        self._state_movement_ui_enabled = is_enabled
        self._script_view.toolbar.set_movement_enabled(is_enabled)

    def _on_setup_template_choice(self, template_kind: DebugTemplateKind) -> None:
        if template_kind == DebugTemplateKind.SCRIPT_SCRATCHPAD:
            self.set_scratch_mode()
        elif template_kind == DebugTemplateKind.TRANSACTION_SPEND:
            self.set_transaction_spend_mode()
        else:
            raise NotImplementedError
        self._stacked_widget.setCurrentWidget(self._script_view)

    def _event_run_script(self) -> None:
        while self._script_view.step_script_evaluation():
            if self._script_view.at_breakpoint():
                # The execution is not finished it just reached a breakpoint.
                return
            if self._script_view.is_blocked():
                # The execution is not finished it just reached something like a placeholder.
                return
        # The execution is finished.
        self.set_debugging_toolbar_enabled(False)

    def _event_step_script(self) -> None:
        if self._script_view.step_script_evaluation():
            return
        # The execution is finished.
        self.set_debugging_toolbar_enabled(False)

    def _event_clear_script(self) -> None:
        self._stacked_widget.setCurrentWidget(self._setup_view)
        self._reset_script_view()

        self._main_stack_view.reset()
        self._alt_stack_view.reset()

        self.set_debugging_toolbar_enabled(False)

    def _event_debugging_movement_blocked(self, is_blocked: bool) -> None:
        self.set_debugging_movement_enabled(not is_blocked)
