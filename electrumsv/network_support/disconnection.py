from concurrent.futures import Future
from typing import cast

from ..exceptions import BadServerError, ServerConnectionError
from ..logs import logs
from .constants import ServerProblemKind
from .exceptions import GeneralAPIError
from .types import ServerStateProtocol

logger = logs.get_logger("server-state-methods")


# Placed here because this is imported by both general_api.py and peer_channel.py and
# avoids circular import
def _on_server_connection_worker_task_done(state: ServerStateProtocol,
        future: Future[None]) -> None:
    """
    This acts as a central point through which execution of worker tasks created by
    `` exit. None of these worker tasks return results, we are solely interested in acting
    on any exceptions that happen within them.

    Worker tasks whose results are passed to this callback:

    - `manage_output_spends_async`
    - `manage_tip_filter_registrations_async`
    - `process_incoming_peer_channel_messages_async`

    WARNING: All these worker tasks run on the asynchronous thread. Because of this we can
        assume that the queue `put_nowait` operation does not have to be thread-safe.

    Raises nothing.
    """
    if future.cancelled():
        return

    disconnection_problem: ServerProblemKind
    disconnection_text: str
    try:
        future.result()
    except BadServerError as bad_server_error:
        # Raised by `manage_output_spends_async`.
        disconnection_problem = ServerProblemKind.BAD_SERVER
        disconnection_text = cast(str, bad_server_error.args[0])
    except ServerConnectionError as server_error:
        # Raised by `manage_output_spends_async`
        # Raised by `process_incoming_peer_channel_messages_async`
        disconnection_problem = ServerProblemKind.CONNECTION_ERROR
        disconnection_text = cast(str, server_error.args[0])
    except GeneralAPIError as general_api_error:
        # Raised by `process_incoming_peer_channel_messages_async`
        disconnection_problem = ServerProblemKind.UNEXPECTED_API_RESPONSE
        disconnection_text = cast(str, general_api_error.args[0])
    else:
        return

    logger.warning("Recorded problem with server %s, %s (%s)", state.server_url,
        disconnection_problem, disconnection_text)

    # WARNING: All these worker tasks run on the asynchronous thread. Because of this we can
    #     assume that the queue `put_nowait` operation does not have to be thread-safe.
    state.disconnection_event_queue.put_nowait((disconnection_problem,
        disconnection_text))

