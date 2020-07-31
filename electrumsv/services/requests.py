import time
from typing import List, Optional, Sequence, Tuple, TYPE_CHECKING
import weakref

from electrumsv.constants import KeyInstanceFlag, PaymentFlag
from electrumsv.logs import logs
from electrumsv.wallet_database.sqlite_support import CompletionCallbackType
from electrumsv.wallet_database.tables import PaymentRequestRow

if TYPE_CHECKING:
    from electrumsv.wallet import AbstractAccount

class RequestService:
    def __init__(self, account: "AbstractAccount") -> None:
        self._account = weakref.proxy(account)
        self._logger = logs.get_logger("key-service")

    def get_request_for_id(self, request_id: int) -> Optional[PaymentRequestRow]:
        wallet = self._account.get_wallet()
        with wallet.get_payment_request_table() as table:
            return table.read_one(request_id=request_id)

    def get_request_for_key_id(self, key_id: int) -> Optional[PaymentRequestRow]:
        wallet = self._account.get_wallet()
        with wallet.get_payment_request_table() as table:
            return table.read_one(keyinstance_id=key_id)

    def create_request(self, keyinstance_id: int, flags: PaymentFlag=PaymentFlag.UNPAID,
                amount: Optional[int]=None, expiration: Optional[int]=None,
                message: Optional[str]=None,
            cb: Optional[CompletionCallbackType]=None) -> PaymentRequestRow:
        wallet = self._account.get_wallet()
        account_id = self._account.get_id()

        # Update the key instance flags, both in acccount cache and the database.
        key = self._account.get_keyinstance(keyinstance_id)
        flags = key.flags | KeyInstanceFlag.IS_PAYMENT_REQUEST
        new_key = key._replace(flags=flags)
        self._account.set_keyinstance(keyinstance_id, new_key)
        wallet.update_keyinstance_flags([ (flags, keyinstance_id) ])

        # Update the payment request next.
        row = PaymentRequestRow(-1, keyinstance_id, flags, amount, expiration, message,
            int(time.time()))
        row = wallet.create_payment_requests([ row ], completion_callback=cb)[0]
        wallet.trigger_callback('on_keys_updated', account_id, [ new_key ])
        return row

    def update_request(self, paymentrequest_id: int, flags: PaymentFlag,
            value: Optional[int]=None, expiration: Optional[int]=None,
            description: Optional[str]=None,
            cb: Optional[CompletionCallbackType]=None) -> PaymentRequestRow:
        row = self.get_request_for_id(paymentrequest_id)
        assert row is not None
        new_row = row._replace(paymentrequest_id=paymentrequest_id, state=flags, value=value,
            expiration=expiration, description=description)

        wallet = self._account.get_wallet()
        entries = [ (flags, value, expiration, description, paymentrequest_id) ]
        with wallet.get_payment_request_table() as table:
            table.update(entries, completion_callback=cb)
        return new_row

    def delete_request(self, paymentrequest_id: int,
            cb: Optional[CompletionCallbackType]=None) -> bool:
        row = self.get_request_for_id(paymentrequest_id)
        if row is None:
            return False

        wallet = self._account.get_wallet()
        account_id = self._account.get_id()

        # Update the key instance flags, both in acccount cache and the database.
        key = self._account.get_keyinstance(row.keyinstance_id)
        flags = key.flags & ~KeyInstanceFlag.IS_PAYMENT_REQUEST
        new_key = key._replace(flags=flags)
        self._account.set_keyinstance(row.keyinstance_id, new_key)
        wallet.update_keyinstance_flags([ (new_key.flags, row.keyinstance_id) ])

        with wallet.get_payment_request_table() as table:
            table.delete([ (paymentrequest_id,) ], cb)

        # TODO: Too soon, the delete event is non-blocking.
        wallet.trigger_callback('on_keys_updated', account_id, [ new_key ])
        return True

    def check_paid_requests(self, checkable_key_ids: Sequence[int],
            exc_value: Optional[Exception]=None) -> None:
        if exc_value is not None:
            raise exc_value

        # TODO: This logic is blocking the database write completion callback. We need a better
        # solution.
        wallet = self._account.get_wallet()
        account_id = self._account.get_id()

        with wallet.get_transaction_delta_table() as td_table:
            paid_key_ids = td_table.read_paid_requests(account_id, list(checkable_key_ids))

            state_updates: List[Tuple[PaymentFlag, int]] = []
            for keyinstance_id in paid_key_ids:
                state_updates.append((PaymentFlag.PAID, keyinstance_id))

        if len(state_updates):
            with wallet.get_payment_request_table() as pr_table:
                pr_table.update_state(state_updates) #,
                    # completion_callback=partial(
                    #     self._dispatch_request_state_change_event, paid_keyinstance_ids))

    def _dispatch_request_state_change_event(self, keyinstance_ids: List[int],
            exc_value: Optional[Exception]=None) -> None:
        if exc_value is not None:
            raise exc_value

        # Other updates happen to update the request list. But this is not guaranteed.
        # If there are problems with the updates not happening, look at using this.
