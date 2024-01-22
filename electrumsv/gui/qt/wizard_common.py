from typing import NamedTuple, Optional

from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QWidget, QWizard

from electrumsv.constants import IntFlag

from .help_dialog import HelpDialog
from .util import FormSectionWidget


class WizardFlags(IntFlag):
    NONE = 0

    # The wizard should offer all standard account creation options.
    STANDARD_MODE = 1
    # The wizard should only offer options that are valid as co-signers in a multisig account.
    MULTISIG_MODE = 2
    ALL_MODES = STANDARD_MODE | MULTISIG_MODE

    # Wizard completion ensures the metadata is externally accessible to the wizard invoking logic.
    METADATA_RESULT = 4
    # Completion of the wizard should result in the account being created in the invoking wallet.
    ACCOUNT_RESULT = 8
    RESULT_MASK = METADATA_RESULT | ACCOUNT_RESULT


DEFAULT_WIZARD_FLAGS = WizardFlags.STANDARD_MODE | WizardFlags.ACCOUNT_RESULT


class HelpContext(NamedTuple):
    file_name: str


class BaseWizard(QWizard):
    HELP_DIRNAME: str

    def __init__(self, parent: Optional[QWidget]=None) -> None:
        super().__init__(parent, Qt.WindowSystemMenuHint | Qt.WindowTitleHint |
            Qt.WindowCloseButtonHint)

        self.setOption(QWizard.IndependentPages, False)
        self.setOption(QWizard.NoDefaultButton, True)
        # The help button is either made visible or hidden when a page is entered, depending
        # on whether the page declares a `HELP_CONTEXT` value.
        self.setOption(QWizard.HaveHelpButton, True)
        self.setOption(QWizard.HelpButtonOnRight, False)

        self.currentIdChanged.connect(self._event_wizard_page_changed)
        self.helpRequested.connect(self._event_help_requested)

    def run(self):
        self.ensure_shown()
        return self.exec()

    def ensure_shown(self) -> None:
        self.show()
        self.raise_()

    # Wiring for pages to know when the wizard switches between them. This is important because
    # pages are instantiated on wizard creation, and reused as the user goes back and forwards
    # between them.
    # TODO: Look at using `initializePage` and `cleanupPage`.
    def _event_wizard_page_changed(self, page_id: int) -> None:
        if self._last_page_id:
            page = self.page(self._last_page_id)
            if hasattr(page, "on_leave"):
                page.on_leave()

        self._last_page_id = page_id
        page = self.page(page_id)
        # Only show the help button if there is help to show for the given page.
        help_context: Optional[HelpContext] = getattr(page, "HELP_CONTEXT", None)
        self.button(QWizard.HelpButton).setVisible(help_context is not None)

        if hasattr(page, "on_enter"):
            page.on_enter()
        else:
            button = self.button(QWizard.CustomButton1)
            button.setVisible(False)

    def _event_help_requested(self) -> None:
        page = self.currentPage()
        help_context: Optional[HelpContext] = getattr(page, "HELP_CONTEXT", None)
        assert help_context is not None
        h = HelpDialog(page, self.HELP_DIRNAME, help_context.file_name)
        h.run()


class WizardFormSection(FormSectionWidget):
    show_help_label: bool = False
    minimum_label_width: int = 120
