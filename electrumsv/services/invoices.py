from typing import List, Optional, TYPE_CHECKING
import weakref

from electrumsv.constants import PaymentFlag
from electrumsv.paymentrequest import PaymentRequest
from electrumsv.wallet_database.sqlite_support import CompletionCallbackType, SynchronousWriter
from electrumsv.wallet_database.tables import InvoiceAccountRow, InvoiceRow

if TYPE_CHECKING:
    from electrumsv.wallet import AbstractAccount

class InvoiceService:
    def __init__(self, account: "AbstractAccount") -> None:
        self._account = weakref.proxy(account)

    def get_invoices(self) -> List[InvoiceAccountRow]:
        # DEFERRED: Ability to change the invoice list to specify what invoices are shown.
        #   This would for instance allow viewing of archived invoices.
        wallet = self._account.get_wallet()
        with wallet.get_invoice_table() as table:
            return table.read_account(self._account.get_id(), PaymentFlag.NONE,
                PaymentFlag.ARCHIVED)

    def get_invoice_for_id(self, invoice_id: int) -> Optional[InvoiceRow]:
        wallet = self._account.get_wallet()
        with wallet.get_invoice_table() as table:
            return table.read_one(invoice_id)

    def get_invoice_for_payment_uri(self, uri: str) -> Optional[InvoiceRow]:
        wallet = self._account.get_wallet()
        with wallet.get_invoice_table() as table:
            return table.read_one(payment_uri=uri)

    def get_invoice_for_tx_hash(self, tx_hash: bytes) -> Optional[InvoiceRow]:
        wallet = self._account.get_wallet()
        with wallet.get_invoice_table() as table:
            return table.read_one(tx_hash=tx_hash)

    def import_payment_request(self, pr: PaymentRequest,
            cb: Optional[CompletionCallbackType]=None) -> InvoiceRow:
        wallet = self._account.get_wallet()

        # We decouple handling of the completion callback from the call.
        with wallet.get_invoice_table() as table:
            # Is this the best algorithm for detecting a duplicate? No idea.
            existing_row = table.read_duplicate(value=pr.get_amount(),
                payment_uri=pr.get_payment_uri())
            if existing_row is not None:
                return existing_row

            # We have a unique constraint on the payment uri to error if we add a duplicate.
            row = InvoiceRow(0, self._account.get_id(), None, pr.get_payment_uri(), pr.get_memo(),
                PaymentFlag.UNPAID, pr.get_amount(), pr.to_json().encode(),
                pr.get_expiration_date(), table._get_current_timestamp())
            table.create([ row ], completion_callback=cb)

        # NOTE: Does not have the invoice id intentionally to reflect it is in progress.
        return row

    def set_invoice_paid(self, invoice_id: int) -> None:
        with self._account.get_wallet().get_invoice_table() as table:
            # Block waiting for the write to succeed here.
            with SynchronousWriter() as writer:
                table.update_flags(
                    # mask, flags
                    [ (PaymentFlag.CLEARED_STATE_MASK, PaymentFlag.PAID, invoice_id) ],
                    completion_callback=writer.get_callback())
                assert writer.succeeded()

    def set_invoice_transaction(self, invoice_id: int, tx_hash: Optional[bytes]=None) -> None:
        with self._account.get_wallet().get_invoice_table() as table:
            # Block waiting for the write to succeed here.
            with SynchronousWriter() as writer:
                table.update_transaction([ (tx_hash, invoice_id) ],
                    completion_callback=writer.get_callback())
                assert writer.succeeded()

    def clear_invoice_transaction(self, tx_hash: bytes) -> None:
        with self._account.get_wallet().get_invoice_table() as table:
            # Block waiting for the write to succeed here.
            with SynchronousWriter() as writer:
                table.clear_transaction([ (tx_hash,) ], completion_callback=writer.get_callback())
                assert writer.succeeded()

    def set_invoice_description(self, invoice_id: int, description: str) -> None:
        wallet = self._account.get_wallet()
        with wallet.get_invoice_table() as table:
            # Block waiting for the write to succeed here.
            with SynchronousWriter() as writer:
                table.update_description([ (description, invoice_id) ],
                    completion_callback=writer.get_callback())
                assert writer.succeeded()

    def delete_invoice(self, invoice_id: int,
            cb: Optional[CompletionCallbackType]=None) -> None:
        wallet = self._account.get_wallet()
        with wallet.get_invoice_table() as table:
            table.delete([ (invoice_id,) ], cb)
