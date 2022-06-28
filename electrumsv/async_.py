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

from asyncio import CancelledError, Event, Lock, Queue, new_event_loop, run_coroutine_threadsafe
import concurrent.futures
from functools import partial
import queue
import threading
from types import TracebackType
from typing import Any, Callable, Coroutine, Optional, ParamSpec, Set, Type, TypeVar

from .logs import logs

logger = logs.get_logger("async")

P1 = ParamSpec("P1")
T1 = TypeVar("T1")
T2 = TypeVar("T2")


class ASync(object):
    '''This helper coordinates setting up an asyncio event loop thread, executing coroutines
    from a different thread, and running completion callbacks in a different thread.
    '''

    def __init__(self) -> None:
        self._queue: queue.Queue[Any] = queue.Queue()
        self.thread = threading.Thread(target=self._main, name="async")
        self.loop = new_event_loop()
        self.start_event = threading.Event()
        self.stop_event = self.event()
        self.futures: Set[concurrent.futures.Future[Any]] = set()

    def event(self) -> Event:
        '''Return an asyncio.Event for our event loop.'''
        return Event()

    def lock(self) -> Lock:
        return Lock()

    def queue(self, maxsize: int=0) -> Queue[Any]:
        '''Return an asyncio.Event for our event loop.'''
        return Queue(maxsize)

    def __enter__(self) -> "ASync":
        logger.debug('starting async thread')
        self.thread.start()
        # Wait for the thread to definitively start before returning
        self.start_event.wait()
        logger.debug('async thread started')
        return self

    def __exit__(self, exc_type: Optional[Type[BaseException]],
            exc_value: Optional[BaseException], traceback: Optional[TracebackType]) \
                -> None:
        # Wait for the thread to definitively stop before returning
        # stop_event must be set from the loop
        logger.debug('stopping async thread')
        self.loop.call_soon_threadsafe(self.stop_event.set)
        self.thread.join()
        logger.debug('async thread stopped')

    async def _wait_until_stopped(self) -> None:
        await self.stop_event.wait()
        for future in list(self.futures):
            future.cancel()

    def _main(self) -> None:
        self.start_event.set()
        self.loop.run_until_complete(self._wait_until_stopped())
        self.loop.close()

    def _collect(self, on_done: Optional[Callable[[concurrent.futures.Future[Any]], None]],
            future: concurrent.futures.Future[Any]) -> None:
        self.futures.remove(future)
        if on_done:
            self._queue.put((on_done, future))
        else:
            try:
                future.result()
            except (CancelledError, concurrent.futures.CancelledError):
                pass
            except Exception:
                logger.exception('async task raised an unhandled exception')

    # WARNING If called directly this will not trigger the pending callbacks and `on_done` will
    #   not happen reliably.
    def spawn(self,
            coroutine: Coroutine[Any, Any, T2],
            on_done: Callable[[concurrent.futures.Future[T2]], None] | None=None) \
                -> concurrent.futures.Future[T2]:
        future = run_coroutine_threadsafe(coroutine, self.loop)
        self.futures.add(future)
        future.add_done_callback(partial(self._collect, on_done))
        return future

    def spawn_and_wait(self, coroutine: Coroutine[Any, Any, T1], timeout: Optional[int]=None) -> T1:
        future = run_coroutine_threadsafe(coroutine, self.loop)
        return future.result(timeout)

    def run_pending_callbacks(self) -> None:
        while not self._queue.empty():
            on_done, future = self._queue.get()
            try:
                on_done(future)
            except Exception:
                logger.exception('unhandled exception in run_pending_callbacks')
