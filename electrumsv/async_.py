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

from asyncio import Event, Queue, new_event_loop, run_coroutine_threadsafe, CancelledError
from concurrent.futures import CancelledError as FCancelledError
from functools import partial
import queue
import threading

from aiorpcx import instantiate_coroutine

from .logs import logs

logger = logs.get_logger("async")


class ASync(object):
    '''This helper coordinates setting up an asyncio event loop thread, executing coroutines
    from a different thread, and running completion callbacks in a different thread.
    '''

    def __init__(self):
        self._queue = queue.Queue()
        self.thread = threading.Thread(target=self._main, name="async")
        self.loop = new_event_loop()
        self.start_event = threading.Event()
        self.stop_event = self.event()
        self.futures = set()

    def event(self):
        '''Return an asyncio.Event for our event loop.'''
        return Event(loop=self.loop)

    def queue(self, maxsize=0):
        '''Return an asyncio.Event for our event loop.'''
        return Queue(maxsize, loop=self.loop)

    def __enter__(self):
        logger.info('starting async thread')
        self.thread.start()
        # Wait for the thread to definitively start before returning
        self.start_event.wait()
        logger.info('async thread started')
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        # Wait for the thread to definitively stop before returning
        # stop_event must be set from the loop
        logger.info('stopping async thread')
        self.loop.call_soon_threadsafe(self.stop_event.set)
        self.thread.join()
        logger.info('async thread stopped')

    async def _wait_until_stopped(self):
        await self.stop_event.wait()
        for future in list(self.futures):
            future.cancel()

    def _main(self):
        self.start_event.set()
        self.loop.run_until_complete(self._wait_until_stopped())
        self.loop.close()

    def _spawn(self, coro, args):
        coro = instantiate_coroutine(coro, args)
        return run_coroutine_threadsafe(coro, self.loop)

    def _collect(self, on_done, future):
        self.futures.remove(future)
        if on_done:
            self._queue.put((on_done, future))
        else:
            try:
                future.result()
            except (CancelledError, FCancelledError):
                pass
            except Exception:
                logger.exception('async task raised an unhandled exception')

    def spawn(self, coro, *args, on_done=None):
        future = self._spawn(coro, args)
        self.futures.add(future)
        future.add_done_callback(partial(self._collect, on_done))
        return future

    def spawn_and_wait(self, coro, *args, timeout=None):
        future = self._spawn(coro, args)
        return future.result(timeout)

    def run_pending_callbacks(self):
        while not self._queue.empty():
            on_done, future = self._queue.get()
            try:
                on_done(future)
            except Exception:
                logger.exception('unhandled exception in run_pending_callbacks')
