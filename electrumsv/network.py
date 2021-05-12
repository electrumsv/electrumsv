 # ElectrumSV - lightweight Bitcoin SV client
# Copyright (C) 2019-2020 The ElectrumSV Developers
# Copyright (c) 2011-2016 Thomas Voegtlin
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

import asyncio
from collections import defaultdict
from contextlib import suppress
from enum import IntEnum
from functools import partial
import json
import os
import random
import re
import ssl
import stat
import time
from typing import Any, cast, Dict, Iterable, List, NamedTuple, Optional, TYPE_CHECKING, Tuple, \
    Union

import aiohttp
from aiohttp import ClientConnectorError
from aiorpcx import (
    connect_rs, RPCSession, Notification, BatchError, RPCError, CancelledError, SOCKSError,
    TaskTimeout, TaskGroup, handler_invocation, sleep, ignore_after, timeout_after,
    SOCKS4a, SOCKS5, SOCKSProxy, SOCKSUserAuth, NewlineFramer
)
from bitcoinx import (
    MissingHeader, IncorrectBits, InsufficientPoW, hex_str_to_hash, hash_to_hex_str,
    sha256, double_sha256
)
import certifi

from .app_state import app_state
from .constants import TxFlags
from .i18n import _
from .logs import logs
from .transaction import Transaction
from .types import ElectrumXHistoryList, ScriptHashSubscriptionEntry
from .util import chunks, JSON, protocol_tuple, TriggeredCallbacks, version_string
from .networks import Net, SVRegTestnet
from .util.misc import decode_response_body
from .version import PACKAGE_VERSION, PROTOCOL_MIN, PROTOCOL_MAX

if TYPE_CHECKING:
    from .wallet import Wallet


logger = logs.get_logger("network")

HEADER_SIZE = 80
ONE_MINUTE = 60
ONE_DAY = 24 * 3600
HEADERS_SUBSCRIBE = 'blockchain.headers.subscribe'
REQUEST_MERKLE_PROOF = 'blockchain.transaction.get_merkle'
SCRIPTHASH_HISTORY = 'blockchain.scripthash.get_history'
SCRIPTHASH_SUBSCRIBE = 'blockchain.scripthash.subscribe'
SCRIPTHASH_UNSUBSCRIBE = 'blockchain.scripthash.unsubscribe'
BROADCAST_TX_MSG_LIST = (
    ('dust', _('very small "dust" payments')),
    (('Missing inputs', 'Inputs unavailable', 'bad-txns-inputs-spent'),
     _('missing, already-spent, or otherwise invalid coins')),
    ('insufficient priority', _('insufficient fees or priority')),
    ('bad-txns-premature-spend-of-coinbase', _('attempt to spend an unmatured coinbase')),
    (('txn-already-in-mempool', 'txn-already-known'),
     _("it already exists in the server's mempool")),
    ('txn-mempool-conflict', _("it conflicts with one already in the server's mempool")),
    ('bad-txns-nonstandard-inputs', _('use of non-standard input scripts')),
    ('absurdly-high-fee', _('fee is absurdly high')),
    ('non-mandatory-script-verify-flag', _('the script fails verification')),
    ('tx-size', _('transaction is too large')),
    ('scriptsig-size', _('it contains an oversized script')),
    ('scriptpubkey', _('it contains a non-standard signature')),
    ('bare-multisig', _('it contains a bare multisig input')),
    ('multi-op-return', _('it contains more than 1 OP_RETURN input')),
    ('scriptsig-not-pushonly', _('a scriptsig is not simply data')),
    ('bad-txns-nonfinal', _("transaction is not final"))
)


def broadcast_failure_reason(exception):
    if isinstance(exception, RPCError):
        msg = exception.message
        for in_msgs, out_msg in BROADCAST_TX_MSG_LIST:
            if isinstance(in_msgs, str):
                in_msgs = (in_msgs, )
            if any(in_msg in msg for in_msg in in_msgs):
                return out_msg
    return _('reason unknown')


class SwitchReason(IntEnum):
    '''The reason the main server was changed.'''
    disconnected = 0
    lagging = 1
    user_set = 2


def _require_list(obj):
    assert isinstance(obj, (tuple, list))
    return obj


def _require_number(obj):
    assert isinstance(obj, (int, float))
    return obj


def _require_string(obj):
    assert isinstance(obj, str)
    return obj


def _history_status(history) -> Optional[str]:
    if not history:
        return None
    status = ''.join(f'{tx_id}:{tx_height}:' for tx_id, tx_height in history)
    return sha256(status.encode()).hex()


def _root_from_proof(hash, branch, index):
    '''From ElectrumX.'''
    for elt in branch:
        if index & 1:
            hash = double_sha256(elt + hash)
        else:
            hash = double_sha256(hash + elt)
        index >>= 1
    if index:
        raise ValueError(f'index {index} out of range for proof of length {len(branch)}')
    return hash


class DisconnectSessionError(Exception):

    def __init__(self, reason, *, blacklist=False):
        super().__init__(reason)
        self.blacklist = False


class SVServerState:
    '''The run-time state of an SVServer.'''

    def __init__(self):
        self.banner = ''
        self.donation_address = ''
        self.last_try = 0.
        self.last_good = 0.
        self.last_blacklisted = 0.
        self.retry_delay = 0
        self.is_disabled = False

    def can_retry(self, now):
        return not self.is_disabled and not self.is_blacklisted(now) and \
            self.last_try + self.retry_delay < now

    def is_blacklisted(self, now):
        return self.last_blacklisted > now - ONE_DAY

    def to_json(self):
        return {
            'last_try': int(self.last_try),
            'last_good': int(self.last_good),
            'last_blacklisted': int(self.last_blacklisted),
        }

    @classmethod
    def from_json(cls, dct):
        result = cls()
        for attr, value in dct.items():
            setattr(result, attr, value)
        return result

    def __str__(self):
        return str(self.to_json())


class SVServerKey(NamedTuple):
    host: str
    port: int
    protocol: str


class SVServer:
    '''A smart wrapper around a (host, port, protocol) tuple.'''

    all_servers: Dict[SVServerKey, 'SVServer'] = {}

    def __init__(self, host: str, port: int, protocol: str) -> None:
        if not isinstance(host, str) or not host:
            raise ValueError(f'bad host: {host}')
        if not isinstance(port, int):
            raise ValueError(f'bad port: {port}')
        if protocol not in 'st':
            raise ValueError(f'unknown protocol: {protocol}')
        key = SVServerKey(host, port, protocol)
        assert key not in SVServer.all_servers
        SVServer.all_servers[key] = self
        # API attributes
        self.host = host
        self.port = port
        self.protocol = protocol
        self.state = SVServerState()

    def key(self) -> SVServerKey:
        return SVServerKey(self.host, self.port, self.protocol)

    @classmethod
    def unique(cls, host: str, port: Union[int, str], protocol: str) -> 'SVServer':
        if isinstance(port, str):
            port = int(port)
        key = SVServerKey(host, port, protocol)
        obj = cls.all_servers.get(key)
        if not obj:
            obj = cls(host, port, protocol)
        return obj

    def update(self, updated_key: SVServerKey) -> None:
        existing_key = self.key()
        assert existing_key != updated_key
        self.host = updated_key.host
        self.port = updated_key.port
        self.protocol = updated_key.protocol
        del self.all_servers[existing_key]
        self.all_servers[updated_key] = self

    def _sslc(self) -> Optional[ssl.SSLContext]:
        if self.protocol != 's':
            return None
        # FIXME: implement certificate pinning like Electrum?
        return ssl.SSLContext(ssl.PROTOCOL_TLS)

    def _connector(self, session_factory, proxy):
        return connect_rs(self.host, self.port, proxy=proxy, session_factory=session_factory,
                          ssl=self._sslc())

    def _logger(self, n):
        logger_name = f'[{self.host}:{self.port} {self.protocol_text()} #{n}]'
        return logs.get_logger(logger_name)

    def to_json(self):
        return (self.host, self.port, self.protocol, self.state)

    @classmethod
    def from_string(cls, s: str) -> 'SVServer':
        parts = s.split(':', 3)
        return cls.unique(*parts)

    @classmethod
    def from_json(cls, data: Tuple[str, int, str, SVServerState]) -> 'SVServer':
        host, port, protocol, state = data
        result = cls.unique(host, port, protocol)
        result.state = state
        return result

    async def connect(self, network: 'Network', logger_name: str) -> None:
        '''Raises: OSError'''
        await sleep(self.state.retry_delay)
        self.state.retry_delay = max(10, min(self.state.retry_delay * 2 + 1, 600))
        logger = self._logger(logger_name)
        logger.info('connecting...')

        self.state.last_try = time.time()
        session_factory = partial(SVSession, network, self, logger)
        async with self._connector(session_factory, proxy=network.proxy) as connected_session:
            session = cast(SVSession, connected_session)
            try:
                await session.run()
            except DisconnectSessionError as error:
                await session.disconnect(str(error), blacklist=error.blacklist)
            except (RPCError, BatchError, TaskTimeout) as error:
                await session.disconnect(str(error))
        logger.info('disconnected')

    def protocol_text(self) -> str:
        if self.protocol == 's':
            return 'SSL'
        return 'TCP'

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, SVServer):
            return NotImplemented
        return self.host == other.host and self.port == other.port and \
            self.protocol == other.protocol

    def __hash__(self) -> int:
        # If we override `__eq__` it makes the object unhashable without `__hash__`.
        return hash((self.host, self.port, self.protocol))

    def __repr__(self) -> str:
        return f'SVServer("{self.host}", {self.port}, "{self.protocol}")'

    def __str__(self) -> str:
        return str(self.to_json()[:3])


class SVUserAuth(SOCKSUserAuth):
    def __repr__(self):
        # So its safe in logs, etc.  Also used in proxy comparisons.
        hash_str = sha256(str((self.username, self.password)).encode())[:8].hex()
        return f'{self.__class__.__name__}({hash_str})'


class SVProxy(SOCKSProxy):
    '''Encapsulates a SOCKS proxy.'''

    kinds = {'SOCKS4' : SOCKS4a, 'SOCKS5': SOCKS5}

    def __init__(self, address, kind, auth):
        protocol = self.kinds.get(kind.upper())
        if not protocol:
            raise ValueError(f'invalid proxy kind: {kind}')
        # This class is serialised using `util.JSON` hooks, this is not possible for `SVUserAuth`
        # as that is naturally serialisable via `json.dumps` and the hook is not called.
        if isinstance(auth, list):
            auth = SVUserAuth(*auth)
        super().__init__(address, protocol, auth)

    def to_json(self):
        return (str(self.address), self.kind(), self.auth)

    @classmethod
    def from_json(cls, obj):
        return cls(*obj)

    @classmethod
    def from_string(cls, obj):
        # Backwards compatibility
        try:
            kind, host, port, username, password = obj.split(':', 5)
            return cls((host, port), kind, SVUserAuth(username, password))
        except Exception:
            return None

    def kind(self):
        return 'SOCKS4' if self.protocol is SOCKS4a else 'SOCKS5'

    def host(self):
        return self.address.host

    def port(self):
        return self.address.port

    def username(self):
        return self.auth.username if self.auth else ''

    def password(self):
        return self.auth.password if self.auth else ''

    def __str__(self):
        return ', '.join((repr(self.address), self.kind(), repr(self.auth)))


class SVSession(RPCSession):

    ca_path = certifi.where()
    _connecting_tips: Dict[bytes, asyncio.Event] = {}
    _need_checkpoint_headers = True
    _script_hash_ids: Dict[bytes, int] = {}
    _have_made_initial_script_hash_subscriptions = False

    def __init__(self, network, server, logger, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._handlers = {}
        self._network = network
        self._closed_event = app_state.async_.event()
        # These attributes are intended to part of the external API
        self.chain = None
        self.logger = logger
        self.server = server
        self.tip = None
        self.ptuple = (0, )

    def set_throttled(self, flag: bool) -> None:
        if flag:
            RPCSession.recalibrate_count = 30
        else:
            RPCSession.recalibrate_count = 10000000000

    def get_current_outgoing_concurrency_target(self) -> int:
        return self._outgoing_concurrency.max_concurrent

    def default_framer(self) -> NewlineFramer:
        max_size = app_state.electrumx_message_size_limit()*1024*1024
        return NewlineFramer(max_size=max_size)

    @classmethod
    def _required_checkpoint_headers(cls):
        '''Returns (start_height, count).  The range of headers needed for the DAA so that all
        post-checkpoint headers can have their difficulty verified.
        '''
        if cls._need_checkpoint_headers:
            headers_obj = app_state.headers
            chain = headers_obj.longest_chain()
            cp_height = headers_obj.checkpoint.height
            if cp_height == 0:
                cls._need_checkpoint_headers = False
            else:
                try:
                    for height in range(cp_height - 146, cp_height):
                        headers_obj.header_at_height(chain, height)
                    cls._need_checkpoint_headers = False
                except MissingHeader:
                    # NOTE(typing) The try scope provides the `height` value.
                    return height, cp_height - height # type: ignore
        return 0, 0

    @classmethod
    def _connect_header(cls, height, raw_header):
        '''It is assumed that if height is <= the checkpoint height then the header has
        been checked for validity.
        '''
        headers_obj = app_state.headers
        checkpoint = headers_obj.checkpoint

        if height <= checkpoint.height:
            headers_obj.set_one(height, raw_header)
            headers_obj.flush()
            header = Net.COIN.deserialized_header(raw_header, height)
            return header, headers_obj.longest_chain()
        else:
            return app_state.headers.connect(raw_header)

    @classmethod
    def _connect_chunk(cls, start_height, raw_chunk):
        '''It is assumed that if the last header of the raw chunk is before the checkpoint height
        then it has been checked for validity.
        '''
        headers_obj = app_state.headers
        checkpoint = headers_obj.checkpoint
        coin = headers_obj.coin
        end_height = start_height + len(raw_chunk) // HEADER_SIZE

        def extract_header(height):
            start = (height - start_height) * HEADER_SIZE
            return raw_chunk[start: start + HEADER_SIZE]

        def verify_chunk_contiguous_and_set(next_raw_header, to_height):
            # Set headers backwards from a proven header, verifying the prev_hash links.
            for height in reversed(range(start_height, to_height)):
                raw_header = extract_header(height)
                if coin.header_prev_hash(next_raw_header) != coin.header_hash(raw_header):
                    raise MissingHeader('prev_hash does not connect')
                headers_obj.set_one(height, raw_header)
                next_raw_header = raw_header

        try:
            # For pre-checkpoint headers with a verified proof, just set the headers after
            # verifying the prev_hash links
            if end_height < checkpoint.height:
                # Set the last proven header
                last_header = extract_header(end_height - 1)
                headers_obj.set_one(end_height - 1, last_header)
                verify_chunk_contiguous_and_set(last_header, end_height - 1)
                return headers_obj.longest_chain()

            # For chunks prior to but connecting to the checkpoint, no proof is required
            verify_chunk_contiguous_and_set(checkpoint.raw_header, checkpoint.height)

            # Process any remaining headers forwards from the checkpoint
            chain = None
            for height in range(max(checkpoint.height + 1, start_height), end_height):
                _header, chain = headers_obj.connect(extract_header(height))

            return chain or headers_obj.longest_chain()
        finally:
            headers_obj.flush()

    async def _negotiate_protocol(self):
        '''Raises: RPCError, TaskTimeout'''
        method = 'server.version'
        args = (PACKAGE_VERSION, [ version_string(PROTOCOL_MIN), version_string(PROTOCOL_MAX) ])
        try:
            server_string, protocol_string = await self.send_request(method, args)
            self.logger.debug("server string: %s", server_string)
            self.logger.debug("negotiated protocol: %s", protocol_string)
            self.ptuple = protocol_tuple(protocol_string)
            assert PROTOCOL_MIN <= self.ptuple <= PROTOCOL_MAX
        except (AssertionError, ValueError) as e:
            raise DisconnectSessionError(f'{method} failed: {e}', blacklist=True)

    async def _get_checkpoint_headers(self):
        '''Raises: RPCError, TaskTimeout'''
        while True:
            start_height, header_count = self._required_checkpoint_headers()
            if not header_count:
                break
            logger.info("%d checkpoint headers needed", header_count)
            await self._request_chunk(start_height, header_count)

    async def _request_chunk(self, start_height, header_count):
        '''Returns the greatest height successfully connected (might be lower than expected
        because of a small server response).

        Raises: RPCError, TaskTimeout, DisconnectSessionError'''
        self.logger.info("requesting %d headers from height %d", header_count, start_height)
        method = 'blockchain.block.headers'
        cp_height = app_state.headers.checkpoint.height
        if start_height + header_count >= cp_height:
            cp_height = 0

        try:
            result = await self.send_request(method, (start_height, header_count, cp_height))

            received_count = result['count']
            last_height = start_height + received_count - 1
            if header_count != received_count:
                self.logger.info("received just %d headers", received_count)

            raw_chunk = bytes.fromhex(result['hex'])
            assert len(raw_chunk) == HEADER_SIZE * received_count
            if cp_height:
                hex_root = result['root']
                branch = [hex_str_to_hash(item) for item in result['branch']]
                self._check_header_proof(hex_root, branch, raw_chunk[-HEADER_SIZE:], last_height)

            self.chain = self._connect_chunk(start_height, raw_chunk)
        except (AssertionError, KeyError, TypeError, ValueError,
                IncorrectBits, InsufficientPoW, MissingHeader) as e:
            raise DisconnectSessionError(f'{method} failed: {e}', blacklist=True)

        self.logger.info("connected %d headers up to height %d", received_count, last_height)
        return last_height

    async def _subscribe_headers(self):
        '''Raises: RPCError, TaskTimeout, DisconnectSessionError'''
        self._handlers[HEADERS_SUBSCRIBE] = self._on_new_tip
        tip = await self.send_request(HEADERS_SUBSCRIBE)
        await self._on_new_tip(tip)

    def _secs_to_next_ping(self):
        return self.last_send + 300 - time.time()

    async def _ping_loop(self):
        '''Raises: RPCError, TaskTimeout'''
        method = 'server.ping'
        while True:
            await sleep(self._secs_to_next_ping())
            if self._secs_to_next_ping() < 1:
                self.logger.debug("sending %s", method)
                await self.send_request(method)

    def _check_header_proof(self, hex_root, branch, raw_header, header_height):
        '''Raises: DisconnectSessionError'''
        expected_root = Net.VERIFICATION_BLOCK_MERKLE_ROOT
        if hex_root != expected_root:
            raise DisconnectSessionError(f'bad header merkle root {hex_root} expected '
                                         f'{expected_root}', blacklist=True)
        header = Net.COIN.deserialized_header(raw_header, header_height)
        proven_root = hash_to_hex_str(_root_from_proof(header.hash, branch, header_height))
        if proven_root != expected_root:
            raise DisconnectSessionError(f'invalid header proof {proven_root} expected '
                                         f'{expected_root}', blacklist=True)
        self.logger.debug("good header proof for height %d", header_height)

    async def _on_new_tip(self, json_tip):
        '''Raises: RPCError, TaskTimeout, DisconnectSessionError'''
        try:
            raw_header = bytes.fromhex(json_tip['hex'])
            height = json_tip['height']
            assert isinstance(height, int), "height must be an integer"
        except Exception as e:
            raise DisconnectSessionError(f'error connecting tip: {e} {json_tip}')

        if height < Net.CHECKPOINT.height:
            raise DisconnectSessionError(f'server tip height {height:,d} below checkpoint')

        self.chain = None
        self.tip = None
        tip = Net.COIN.deserialized_header(raw_header, height)

        while True:
            try:
                self.tip, self.chain = self._connect_header(tip.height, tip.raw)
                self.logger.debug('connected tip at height %d', height)
                self._network.check_main_chain_event.set()
                self._network.check_main_chain_event.clear()
                return
            except (IncorrectBits, InsufficientPoW) as e:
                raise DisconnectSessionError(f'bad header provided: {e}', blacklist=True)
            except MissingHeader:
                pass
            # Try to connect and then re-check.  Note self.tip might have changed.
            await self._catch_up_to_tip_throttled(tip)

    async def _catch_up_to_tip_throttled(self, tip):
        '''Raises: DisconnectSessionError, BatchError, TaskTimeout'''
        # Avoid thundering herd effect by having one session catch up per tip
        done_event = SVSession._connecting_tips.get(tip.raw)
        if done_event:
            self.logger.debug('another session is connecting my tip %s', tip.hex_str())
            await done_event.wait()
        else:
            self.logger.debug('connecting my own tip %s', tip.hex_str())
            SVSession._connecting_tips[tip.raw] = app_state.async_.event()
            try:
                await self._catch_up_to_tip(tip)
            finally:
                SVSession._connecting_tips.pop(tip.raw).set()

    async def _catch_up_to_tip(self, tip):
        '''Raises: DisconnectSessionError, BatchError, TaskTimeout'''
        headers_obj = app_state.headers
        cp_height = headers_obj.checkpoint.height
        max_height = max(chain.height for chain in headers_obj.chains())
        heights = [cp_height + 1]
        step = 1
        height = min(tip.height, max_height)
        while height > cp_height:
            heights.append(height)
            height -= step
            step += step

        height = await self._request_headers_at_heights(heights)
        # Catch up
        while height < tip.height:
            height = await self._request_chunk(height + 1, 2016)

    async def _subscribe_to_script_hash(self, script_hash_hex: str) -> None:
        """
        Subscribe for status change events for the given script hash.

        This call will either return a status hash or `None`. `None` indicates that the indexing
        server considers the script hash to not have any use.

        Raises: RPCError, TaskTimeout
        """
        status = await self.send_request(SCRIPTHASH_SUBSCRIBE, [script_hash_hex])
        await self._on_queue_status_changed(script_hash_hex, status)

    async def _unsubscribe_from_script_hash(self, script_hash: str) -> bool:
        return await self.send_request(SCRIPTHASH_UNSUBSCRIBE, [script_hash])

    async def _on_script_hash_status_changed(self, script_hash: str, status: Optional[str]) -> None:
        script_hash_bytes = hex_str_to_hash(script_hash)
        subscription_id = self._script_hash_ids.get(script_hash_bytes)
        if subscription_id is None:
            self.logger.error("received status notification for unsubscribed %s", script_hash)
            return

        result: ElectrumXHistoryList = []
        if status is not None:
            # This returns a list of first the confirmed transactions in blockchain order followed
            # by the mempool transactions. Only the mempool transactions have a fee value, and they
            # are in arbitrary order.
            result = await self.request_history(script_hash)

        self.logger.debug("received history for %s length %d", subscription_id, len(result))

        await app_state.subscriptions.on_script_hash_history(subscription_id, script_hash_bytes,
            result)

    async def _main_server_batch(self):
        '''Raises: DisconnectSessionError, BatchError, TaskTimeout'''
        # NOTE(typing) We know `timeout_after` will be returning a context manager.
        async with timeout_after(10): # type: ignore
            async with self.send_batch(raise_errors=True) as batch:
                batch.add_request('server.banner')
                batch.add_request('server.donation_address')
                batch.add_request('server.peers.subscribe')
        server = self.server
        try:
            server.state.banner = _require_string(batch.results[0])
            server.state.donation_address = _require_string(batch.results[1])
            server.state.peers = self._parse_peers_subscribe(batch.results[2])
            self._network.trigger_callback('banner')
        except AssertionError as e:
            raise DisconnectSessionError(f'main server requests bad batch response: {e}')

    def _parse_peers_subscribe(self, result):
        peers = []
        for host_details in _require_list(result):
            host_details = _require_list(host_details)
            host = _require_string(host_details[1])
            for v in host_details[2]:
                if re.match(r"[st]\d*", _require_string(v)):
                    protocol, port = v[0], v[1:]
                    try:
                        peers.append(SVServer.unique(host, port, protocol))
                    except ValueError:
                        pass
        self.logger.info("%d servers returned from server.peers.subscribe", len(peers))
        return peers

    async def _request_headers_at_heights(self, heights):
        '''Requests the headers as a batch and connects them, lowest height first.

        Return the greatest connected height (-1 if none connected).
        Raises: DisconnectSessionError, BatchError, TaskTimeout
        '''
        async def _request_header_batch(batch_heights):
            nonlocal good_height

            self.logger.debug("requesting %d headers at heights %s", len(batch_heights),
                batch_heights)
            # NOTE(typing) We know `timeout_after` will be returning a context manager.
            async with timeout_after(10): # type: ignore
                async with self.send_batch(raise_errors=True) as batch:
                    for height in batch_heights:
                        batch.add_request(method,
                                          (height, cp_height if height <= cp_height else 0))

            try:
                for result, height in zip(batch.results, batch_heights):
                    if height <= cp_height:
                        hex_root = result['root']
                        branch = [hex_str_to_hash(item) for item in result['branch']]
                        raw_header = bytes.fromhex(result['header'])
                        self._check_header_proof(hex_root, branch, raw_header, height)
                    else:
                        raw_header = bytes.fromhex(result)
                    _header, self.chain = self._connect_header(height, raw_header)
                    good_height = height
            except MissingHeader:
                # NOTE(typing) The try scope provides `raw_header` and `height` values.
                hex_str = hash_to_hex_str(Net.COIN.header_hash(raw_header)) # type: ignore
                self.logger.info("failed to connect at height %d, hash %s last good %d",
                    height, hex_str, good_height) # type: ignore
            except (AssertionError, KeyError, TypeError, ValueError) as e:
                raise DisconnectSessionError(f'bad {method} response: {e}')

        heights = sorted(set(heights))
        cp_height = Net.CHECKPOINT.height
        method = 'blockchain.block.header'
        good_height = -1
        min_good_height = max((height for height in heights if height <= cp_height), default=-1)
        for chunk in chunks(heights, 100):
            await _request_header_batch(chunk)
        if good_height < min_good_height:
            raise DisconnectSessionError(f'cannot connect to checkpoint', blacklist=True)
        return good_height

    async def handle_request(self, request):
        if isinstance(request, Notification):
            handler = self._handlers.get(request.method)
        else:
            handler = None
        coro = handler_invocation(handler, request)()
        return await coro

    async def connection_lost(self):
        await super().connection_lost()
        self._closed_event.set()

    #
    # API exposed to the rest of this file
    #

    async def disconnect(self, reason, *, blacklist=False):
        if blacklist:
            self.server.state.last_blacklisted = time.time()
            self.logger.error("disconnecting and blacklisting: %s", reason)
        else:
            self.logger.error("disconnecting: %s", reason)
        await self.close()

    async def run(self):
        '''Called when a connection is established to manage the connection.

        Raises: RPCError, BatchError, TaskTimeout, DisconnectSessionError
        '''
        # Negotiate the protocol before doing anything else
        await self._negotiate_protocol()
        # Checkpoint headers are essential to attempting tip connection
        await self._get_checkpoint_headers()
        # Then subscribe headers and connect the server's tip
        await self._subscribe_headers()
        # Only once the tip is connected to our set of chains do we consider the
        # session good and add it to the network's session list.  The network and
        # other client code can assume a session 'tip' and 'chain' set.
        is_main_server = await self._network.session_established(self)
        try:
            self.server.state.retry_delay = 0
            async with TaskGroup() as group:
                if is_main_server:
                    self.logger.info('using as main server')
                    await group.spawn(self._main_server_batch)
                # This raises a TaskTimeout but it gets discarded as it also seems to trigger
                # the closed event which cancels the ping exception before that gets raised up.
                await group.spawn(self._ping_loop)
                await self._closed_event.wait()
                await group.cancel_remaining()
        finally:
            await self._network.session_closed(self)

    async def headers_at_heights(self, heights):
        '''Raises: MissingHeader, DisconnectSessionError, BatchError, TaskTimeout'''
        result = {}
        missing = []
        header_at_height = app_state.headers.header_at_height
        for height in set(heights):
            try:
                result[height] = header_at_height(self.chain, height)
            except MissingHeader:
                missing.append(height)
        if missing:
            await self._request_headers_at_heights(missing)
            for height in missing:
                result[height] = header_at_height(self.chain, height)
        return result

    async def request_tx(self, tx_id: str):
        '''Raises: RPCError, TaskTimeout'''
        return await self.send_request('blockchain.transaction.get', [tx_id])

    async def request_proof(self, *args):
        '''Raises: RPCError, TaskTimeout'''
        return await self.send_request(REQUEST_MERKLE_PROOF, args)

    async def request_history(self, script_hash_hex: str) -> ElectrumXHistoryList:
        '''Raises: RPCError, TaskTimeout'''
        return await self.send_request(SCRIPTHASH_HISTORY, [script_hash_hex])

    async def _on_queue_status_changed(self, script_hash_hex: str, status: str) -> None:
        item = (script_hash_hex, status)
        self._network._on_status_queue.put_nowait(item)

    async def subscribe_to_script_hashes(self, entries: List[ScriptHashSubscriptionEntry],
            initial_subscription: bool=False) -> None:
        '''Raises: RPCError, TaskTimeout'''
        # Ensure that we ignore the subscription requests that happen before we get the initial
        # subscription, otherwise we would subscribe to those script hashes twice.
        if initial_subscription:
            self._have_made_initial_script_hash_subscriptions = True
            self.logger.debug("Initial script hash subscriptions (%d)", len(entries))
        elif not self._have_made_initial_script_hash_subscriptions:
            self.logger.debug("Ignored script hash subscriptions (%d too early)", len(entries))
            return

        self._handlers[SCRIPTHASH_SUBSCRIBE] = self._on_queue_status_changed

        async with TaskGroup() as group:
            for entry in entries:
                self._script_hash_ids[entry.script_hash] = entry.entry_id

                script_hash_hex = hash_to_hex_str(entry.script_hash)
                await group.spawn(self._subscribe_to_script_hash(script_hash_hex))

    async def unsubscribe_from_script_hashes(self, entries: List[ScriptHashSubscriptionEntry]) \
            -> None:
        """
        Unsubscribe from the given script hashes.

        It is a given that there is nothing else wanting status changes for these script hashes
        because we are getting events through the global subscription object.

        Raises: RPCError, TaskTimeout
        """
        if self.ptuple < (1, 4, 2):
            self.logger.debug("negotiated protocol does not support unsubscribing")
            return

        async with TaskGroup() as group:
            for entry in entries:
                del self._script_hash_ids[entry.script_hash]

                script_hash_hex = hash_to_hex_str(entry.script_hash)
                await group.spawn(self._unsubscribe_from_script_hash(script_hash_hex))


class Network(TriggeredCallbacks):
    '''Manages a set of connections to remote ElectrumX servers.  All operations are
    asynchronous.
    '''

    def __init__(self):
        TriggeredCallbacks.__init__(self)

        app_state.read_headers()

        # Sessions
        self.sessions: List[SVSession] = []
        self._electrumx_disconnection_events: dict[SVServerKey, asyncio.Event] = {}
        self._chosen_servers: set[SVServer] = set()
        self.main_server = None
        self.mapi_servers = self._read_config_mapi()
        self.proxy = None

        # Events
        self.sessions_changed_event = app_state.async_.event()
        self.check_main_chain_event = app_state.async_.event()
        self.stop_network_event = app_state.async_.event()
        self.shutdown_complete_event = app_state.async_.event()

        # Add an wallet, remove an wallet, or redo all wallet verifications
        self._wallet_jobs = app_state.async_.queue()

        # Feed pub-sub notifications to currently active SVSession for processing
        self._on_status_queue = app_state.async_.queue()

        dir_path = app_state.config.file_path('certs')
        if not os.path.exists(dir_path):
            os.mkdir(dir_path)
            os.chmod(dir_path, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)

        self.future = app_state.async_.spawn(self._main_task)

        app_state.subscriptions.set_script_hash_callbacks(
            self._on_subscribe_script_hashes, self._on_unsubscribe_script_hashes)
        self.mapi_client: Optional[aiohttp.ClientSession] = None

    def _read_config_mapi(self):
        mapi_servers = app_state.config.get("mapi_servers", [])
        if mapi_servers:
            logger.info("read %d merchant api servers from config file", len(mapi_servers))
        for mapi_server in Net.DEFAULT_MAPI_SERVERS:
            if mapi_server['uri'] not in [mapi_server['uri'] for mapi_server in mapi_servers]:
                mapi_servers.append(mapi_server)
        return mapi_servers

    async def _get_mapi_client(self):
        # aiohttp session needs to be initialised in async function
        # https://github.com/tiangolo/fastapi/issues/301
        if self.mapi_client is None:
            # resolver = AsyncResolver()
            # conn = aiohttp.TCPConnector(family=socket.AF_INET, resolver=resolver,
            #      ttl_dns_cache=10,
            #                             force_close=True, enable_cleanup_closed=True)
            # self.mapi_client = aiohttp.ClientSession(connector=conn)
            self.mapi_client = aiohttp.ClientSession()
        return self.mapi_client

    async def _close_mapi_client(self) -> None:
        logger.debug("closing aiohttp client session.")
        if self.mapi_client:
            await self.mapi_client.close()

    async def _main_task(self) -> None:
        try:
            async with TaskGroup() as group:
                await group.spawn(self._start_network, group)
                await group.spawn(self._monitor_lagging_sessions)
                await group.spawn(self._monitor_main_chain)
                await group.spawn(self._initial_script_hash_status_subscriptions, group)
                await group.spawn(self._monitor_script_hash_status_subscriptions, group)
                await group.spawn(self._monitor_wallets, group)
                await group.spawn(self._monitor_mapi_servers)
        finally:
            self.shutdown_complete_event.set()
            app_state.config.set_key('servers', list(SVServer.all_servers.values()), True)
            app_state.config.set_key('mapi_servers', self.get_mapi_servers(), True)

    async def _do_mapi_health_check(self) -> None:
        """The last_good and last_try timestamps will be used to include/exclude the mAPI for
        selection"""
        return
        now = time.time()
        for i, mapi_server in enumerate(self.mapi_servers):
            mapi_server['last_try'] = now
            uri = mapi_server['uri'] + "/feeQuote"
            headers = {'Content-Type': 'application/json'}
            if Net._net is SVRegTestnet:
                ssl = False
            else:
                ssl = True

            assert self.mapi_client is not None
            async with self.mapi_client.get(uri, headers=headers, ssl=ssl) as resp:
                try:
                    json_response = await decode_response_body(resp)
                except (ClientConnectorError, ConnectionError, OSError, SOCKSError):
                    logger.error("failed connecting to %s", mapi_server['uri'])
                else:
                    if resp.status != 200:
                        logger.error("feeQuote request to %s failed with: status: %s, reason: %s",
                            mapi_server['uri'], resp.status, resp.reason)
                    else:
                        assert json_response['encoding'].lower() == 'utf-8'
                        json_payload = json.loads(json_response['payload'])
                        logger.debug("valid feeQuote received from %s", mapi_server['uri'])
                        mapi_server['last_good'] = now
                        mapi_server['fee'] = json_payload
                finally:
                    self.mapi_servers[i] = mapi_server

        # update mapi servers in json config
        app_state.config.set_key('mapi_servers', self.mapi_servers, True)

    async def _monitor_mapi_servers(self) -> None:
        if not self.mapi_client:
            self.mapi_client = await self._get_mapi_client()

        if self.mapi_servers is None:
            self._read_config_mapi()

        while True:
            await self._do_mapi_health_check()
            await asyncio.sleep(60)

    async def _restart_network(self) -> None:
        self.stop_network_event.set()

    async def _start_network(self, group: TaskGroup) -> None:
        while True:
            # Treat all servers as not used so connections are not delayed
            for server in SVServer.all_servers.values():
                server.state.retry_delay = 0

            if self.main_server is None:
                self.main_server, self.proxy = self._read_config_electrumx()

            logger.debug('starting...')
            connections_task = await group.spawn(self._maintain_connections)
            await self.stop_network_event.wait()
            self.stop_network_event.clear()
            with suppress(CancelledError):
                await connections_task

    async def _maintain_connections(self) -> None:
        count = 1 if app_state.config.get('oneserver') else 10
        async with TaskGroup() as group:
            for n in range(0, count):
                await group.spawn(self._maintain_connection, n)

    async def _maintain_connection(self, n: int) -> None:
        # Connection 0 initially connects to the main_server.  main_server can change if
        # auto_connect is true, or the user specifies a new one in the network dialog.
        server = self.main_server if n == 0 else None
        while True:
            if server is self.main_server:
                self.trigger_callback('status')
            else:
                server = await self._random_server(self.main_server.protocol)
            assert server is not None

            server_key = server.key()
            disconnection_event = app_state.async_.event()
            self._electrumx_disconnection_events[server_key] = disconnection_event
            self._chosen_servers.add(server)
            try:
                await server.connect(self, str(n))
            except (OSError, SOCKSError) as e:
                logger.error("%s connection error: %s", server, str(e))
            finally:
                self._chosen_servers.remove(server)
                del self._electrumx_disconnection_events[server_key]

            disconnection_event.set()
            disconnection_event.clear()

            if server is self.main_server:
                await self._maybe_switch_main_server(SwitchReason.disconnected)

    async def _maybe_switch_main_server(self, reason: SwitchReason) -> None:
        now = time.time()
        max_height = max((session.tip.height for session in self.sessions
            if session.tip is not None), default=0)
        for session in self.sessions:
            if session.tip is not None and session.tip.height > max_height - 2:
                session.server.state.last_good = now
        # Give a 60-second breather for a lagging server to catch up
        good_servers = [session.server for session in self.sessions
                        if session.server.state.last_good > now - 60]
        if not good_servers:
            logger.warning('no good servers available')
        elif self.main_server not in good_servers:
            if self.auto_connect():
                await self._set_main_server(random.choice(good_servers), reason)
            else:
                logger.warning("main server %s is not good, but retaining it because "
                    "auto-connect is off", self.main_server)

    async def _monitor_lagging_sessions(self) -> None:
        '''Monitor which sessions are lagging.

        If the main server is lagging switch the main server if auto_connect.
        '''
        while True:
            # NOTE(typing) We know `timeout_after` will be returning a context manager.
            async with ignore_after(20): # type: ignore
                await self.sessions_changed_event.wait()
            await self._maybe_switch_main_server(SwitchReason.lagging)

    async def _on_subscribe_script_hashes(self, entries: List[ScriptHashSubscriptionEntry]) -> None:
        """
        Process wallet script hash subscription requests.

        This is non-blocking and if there is no main session we do not need to subscribe, and
        the initial subscription logic that happens on main server connection should take care of
        it for us.
        """
        session = self.main_session()
        if session is not None:
            session.logger.debug('Subscribing to %d script hashes', len(entries))
            await session.subscribe_to_script_hashes(entries)

    async def _on_unsubscribe_script_hashes(self, entries: List[ScriptHashSubscriptionEntry]) \
            -> None:
        """
        Process wallet script hash unsubscription requests.

        This is non-blocking and if there is no main session then it will simply not have anything
        to unsubscribe.
        """
        session = self.main_session()
        if session is not None:
            session.logger.debug("Unsubscribing from %d script hashes", len(entries))
            await session.unsubscribe_from_script_hashes(entries)

    async def _monitor_wallets(self, group: TaskGroup) -> None:
        tasks = {}
        while True:
            job, wallet = await self._wallet_jobs.get()
            if job == 'add':
                if wallet not in tasks:
                    tasks[wallet] = await group.spawn(self._maintain_wallet(wallet))
            elif job == 'remove':
                if wallet in tasks:
                    tasks.pop(wallet).cancel()
            elif job == 'undo_verifications':
                above_height = wallet
                for wallet in tasks:
                    wallet.undo_verifications(above_height)
            elif job == 'check_verifications':
                for wallet in tasks:
                    wallet.txs_changed_event.set()
            else:
                logger.error('unknown wallet job %s', job)

    async def _monitor_main_chain(self) -> None:
        main_chain = None
        while True:
            await self.check_main_chain_event.wait()
            main_session = await self._main_session()
            new_main_chain = main_session.chain
            if main_chain != new_main_chain and main_chain:
                _chain, above_height = main_chain.common_chain_and_height(new_main_chain)
                logger.info("main chain updated; undoing wallet verifications above height %d",
                    above_height)
                await self._wallet_jobs.put(('undo_verifications', above_height))
            # It has been observed that we may receive headers after all the history events that
            # relate to the height of those headers. Queueing a check here will cover those new
            # headers and also due to sequential nature of jobs undo any existing ones first.
            await self._wallet_jobs.put(('check_verifications', None))
            main_chain = new_main_chain
            # TODO(deferred) We get triggered every time any server we are connected to gets a
            #   new tip. This means that it is possible that all the UI elements will end up
            #   refreshing (even if every 500 ms due to the timer choke which I observed happening
            #   when I noticed this, so it does happen).
            self.trigger_callback('updated')
            self.trigger_callback('main_chain', main_chain, new_main_chain)

    async def _set_main_server(self, server: SVServer, reason: SwitchReason) -> None:
        '''Set the main server to something new.'''
        assert isinstance(server, SVServer), f"got invalid server value: {server}"
        logger.info("switching main server to: '%s' reason: %s", server, reason.name)
        old_main_session = self.main_session()
        self.main_server = server
        self.check_main_chain_event.set()
        self.check_main_chain_event.clear()
        # This event is typically generated when sessions are both established and closed.
        # We need to generate it here to wake up all the things that may be waiting for main
        # sessions, given that an existing session can be upgraded to a main session.
        self.sessions_changed_event.set()
        self.sessions_changed_event.clear()
        _main_session = self.main_session()
        # Disconnect the old main session, if any, in order to lose scripthash
        # subscriptions.
        if old_main_session:
            if reason == SwitchReason.user_set:
                old_main_session.server.retry_delay = 0
            await old_main_session.close()
        self.trigger_callback('status')

    async def update_electrumx_server_async(self, existing_key: SVServerKey,
            updated_key: SVServerKey) -> None:
        """
        Update the connection parameters for a given server instance.

        This will take offline and disconnect a server before updating the parameters, the server
        will be disabled for the duration of the update and left disabled if it was already so.
        """
        server = SVServer.all_servers.get(existing_key)
        if server is None:
            raise KeyError("server does not exist")

        if updated_key.protocol not in 'st':
            raise ValueError(f'unknown protocol: {updated_key.protocol}')

        if updated_key in SVServer.all_servers:
            raise KeyError("server already exists with updated parameters")

        # We do not want to leak the disabling of the server here (assuming the user did not
        # manually disable it) so we override it to be disabled and preserve the existing value
        # to restore it.
        was_disabled = server.state.is_disabled
        server.state.is_disabled = True
        try:
            for session in self.sessions:
                if session.server is server:
                    # This should cause the blocking `SVServer.connect` call to exit.
                    await session.close()
                    break

            # If the server was connected, ensure it is no longer connected.
            if server.key() in self._electrumx_disconnection_events:
                await self._electrumx_disconnection_events[server.key()].wait()
            assert server not in self._chosen_servers
            server.update(updated_key)
        finally:
            server.state.is_disabled = was_disabled

    def update_electrumx_server(self, existing_key: SVServerKey, updated_key: SVServerKey) \
            -> None:
        return app_state.async_.spawn_and_wait(self.update_electrumx_server_async,
            existing_key, updated_key)

    def _read_config_electrumx(self):
        # Remove obsolete key
        app_state.config.set_key('server_blacklist', None)
        # The way SVServers are read from config.json is confusing. JSON.register() is called for
        # SVServer and when the config is deserialized, the SVServer adds itself to the
        # class level list of "all_servers"
        # TODO
        logger.info('Read %d electrumx servers from config file', len(SVServer.all_servers))
        # Add default servers if not present. If we add the ability for users to delete servers
        # and they want to delete default serves, then this will override that.
        for host, data in Net.DEFAULT_SERVERS.items():
            for protocol in 'st':
                if protocol in data:
                    SVServer.unique(host, data[protocol], protocol)

        main_server = app_state.config.get('server', None)
        if isinstance(main_server, str):
            main_server = SVServer.from_string(main_server)
            app_state.config.set_key('server', main_server, True)
        if not isinstance(main_server, SVServer):
            logger.info('choosing an SSL server randomly; none in config')
            main_server = self._random_server_nowait('s')
            if not main_server:
                raise RuntimeError('no servers available')

        proxy = app_state.config.get('proxy', None)
        if isinstance(proxy, str):
            proxy = SVProxy.from_string(proxy)

        logger.info("main server: %s, proxy: %s", main_server, proxy)
        return main_server, proxy

    async def _request_transactions(self, wallet, missing_hashes: List[bytes]) -> bool:
        wallet.request_count += len(missing_hashes)
        wallet.progress_event.set()
        had_timeout = False
        session = await self._main_session()
        session.logger.debug("requesting %d missing transactions", len(missing_hashes))
        async with TaskGroup() as group:
            tasks = {}
            for tx_hash in missing_hashes:
                tx_id = hash_to_hex_str(tx_hash)
                tasks[await group.spawn(session.request_tx(tx_id))] = tx_hash

            while tasks:
                task = await group.next_done()
                wallet.response_count += 1
                wallet.progress_event.set()
                tx_hash = tasks.pop(task)
                tx_id = hash_to_hex_str(tx_hash)
                try:
                    tx_hex = task.result()
                    tx = Transaction.from_hex(tx_hex)
                    session.logger.debug("received tx %s, bytes: %d", tx_id, len(tx_hex)//2)
                except CancelledError:
                    had_timeout = True
                except Exception:
                    logger.exception('unexpected error fetching transaction %s', tx_id)
                else:
                    await wallet.import_transaction_async(tx_hash, tx, TxFlags.STATE_CLEARED,
                        external=True)
        return had_timeout

    def _available_servers(self, protocol):
        now = time.time()
        unchosen = set(SVServer.all_servers.values()).difference(self._chosen_servers)
        return [server for server in unchosen
                if server.protocol == protocol and server.state.can_retry(now)]

    def _random_server_nowait(self, protocol):
        servers = self._available_servers(protocol)
        return random.choice(servers) if servers else None

    async def _random_server(self, protocol):
        while True:
            server = self._random_server_nowait(protocol)
            if server:
                return server
            await sleep(10)

    async def _request_proofs(self, wallet: 'Wallet', wanted_map: Dict[bytes, int]) -> bool:
        had_timeout = False
        session = await self._main_session()
        session.logger.debug("requesting %d proofs", len(wanted_map))
        async with TaskGroup() as group:
            tasks = {}
            for tx_hash, tx_height in wanted_map.items():
                tx_id = hash_to_hex_str(tx_hash)
                tasks[await group.spawn(session.request_proof(tx_id, tx_height))] = (tx_hash,
                    tx_id)
            headers = await session.headers_at_heights(wanted_map.values())

            while tasks:
                task = await group.next_done()
                tx_hash, tx_id = tasks.pop(task)
                block_height = wanted_map[tx_hash]
                try:
                    result = task.result()
                    branch = [hex_str_to_hash(item) for item in result['merkle']]
                    tx_pos = result['pos']
                    proven_root = _root_from_proof(tx_hash, branch, tx_pos)
                    header = headers[block_height]
                except CancelledError:
                    had_timeout = True
                except Exception as e:
                    logger.error("failed obtaining proof for %s: %s", tx_id, str(e))
                else:
                    if header.merkle_root == proven_root:
                        logger.debug("received valid proof for %s", tx_id)
                        await wallet.add_transaction_proof(tx_hash, block_height, header,
                            tx_pos, tx_pos, branch)
                    else:
                        logger.error("invalid proof for tx %s in block %s: got %s, expected %s",
                            tx_id, hash_to_hex_str(header.hash), hash_to_hex_str(proven_root),
                            hash_to_hex_str(header.merkle_root))
        return had_timeout

    async def _initial_script_hash_status_subscriptions(self, group: TaskGroup) -> None:
        """
        Ensure that all existing script hashes are registered with the main server.

        Raises: RPCError, TaskTimeout
        """
        while True:
            logger.info("Pending subscription to script hashes")
            await self.check_main_chain_event.wait()
            main_session = await self._main_session()
            entries = app_state.subscriptions.read_script_hashes()
            main_session.logger.info("Subscribing to %d script hashes", len(entries))
            await main_session.subscribe_to_script_hashes(entries, initial_subscription=True)
            # When we switch main servers we close the connection to the old main server. This
            # will trigger the next iteration for any subsequent main server.
            await main_session._closed_event.wait()

    async def _monitor_script_hash_status_subscriptions(self, group: TaskGroup) -> None:
        """
        Process all incoming script hash status events and queue for processing.

        The sole reason this function exists is to ensure that events do not sit in the aiorpcx
        queue for too long. If that happens then they get discarded, or some error happens. So
        instead we promptly take them from the queue and dispatch them for processing in a
        task per item.
        """
        while True:
            session = await self._main_session()
            script_hash, status = await self._on_status_queue.get()
            await group.spawn(session._on_script_hash_status_changed, script_hash, status)

    async def _monitor_txs(self, wallet: 'Wallet') -> None:
        '''Raises: RPCError, BatchError, TaskTimeout, DisconnectSessionError'''
        # When the wallet receives notification of new transactions, it signals that this
        # monitoring loop should awaken. The loop retrieves all outstanding transaction data and
        # proofs in parallel. However, the prerequisite for needing a proof for a transaction is
        # first having it's data. So after fetching transactions, it becomes necessary to fetch
        # proofs again, and loop at least twice. So this loop only blocks if it knows for sure
        # there are no outstanding needs for either transaction data or proof.
        while True:
            # The set of transactions we know about, but lack the actual transaction data for.
            wanted_tx_map = await wallet.get_missing_transactions_async()
            # The set of transactions we have data for, but not proof for.
            wanted_proof_map = await wallet.get_unverified_transactions_async()

            coros = []
            if wanted_tx_map:
                coros.append(self._request_transactions(wallet, wanted_tx_map))
            if wanted_proof_map:
                coros.append(self._request_proofs(wallet, wanted_proof_map))
            if not coros:
                await wallet.txs_changed_event.wait()
                wallet.txs_changed_event.clear()

            async with TaskGroup() as group:
                for coro in coros:
                    await group.spawn(coro)

    async def _maintain_wallet(self, wallet: 'Wallet') -> None:
        '''Put all tasks for a single wallet in a group so they can be cancelled together.'''
        logger.info('maintaining wallet %s', wallet)
        try:
            while True:
                try:
                    async with TaskGroup() as group:
                        await group.spawn(self._monitor_txs, wallet)
                except (RPCError, BatchError, DisconnectSessionError, TaskTimeout) as error:
                    blacklist = isinstance(error, DisconnectSessionError) and error.blacklist
                    session = self.main_session()
                    if session:
                        await session.disconnect(str(error), blacklist=blacklist)
        finally:
            logger.info('stopped maintaining %s', wallet)

    async def _main_session(self) -> 'SVSession':
        while True:
            session = self.main_session()
            if session:
                return session
            await self.sessions_changed_event.wait()

    async def _random_session(self) -> SVSession:
        while not self.sessions:
            logger.info('waiting for new session')
            await self.sessions_changed_event.wait()
        return random.choice(self.sessions)

    #
    # API exposed to SVSession
    #

    async def session_established(self, session) -> bool:
        self.sessions.append(session)
        self.sessions_changed_event.set()
        self.sessions_changed_event.clear()
        self.trigger_callback('sessions')
        if session.server is self.main_server:
            self.trigger_callback('status')
            return True
        return False

    async def session_closed(self, session) -> None:
        self.sessions.remove(session)
        self.sessions_changed_event.set()
        self.sessions_changed_event.clear()
        if session.server is self.main_server:
            self.trigger_callback('status')
        self.trigger_callback('sessions')

    #
    # External API
    #

    async def shutdown_wait(self) -> None:
        self.future.cancel()
        await self.shutdown_complete_event.wait()
        assert not self.sessions
        logger.warning('stopped')

    def auto_connect(self) -> bool:
        return app_state.config.get('auto_connect', True)

    def is_connected(self) -> bool:
        return self.main_session() is not None

    def main_session(self) -> Optional['SVSession']:
        '''Returns the session, if any, connected to main_server.'''
        for session in self.sessions:
            if session.server is self.main_server:
                return session
        return None

    def get_servers(self) -> Iterable[SVServer]:
        return SVServer.all_servers.values()

    def get_server(self, key: SVServerKey) -> SVServer:
        """
        Raises `KeyError` if the server does not exist.
        """
        return SVServer.all_servers[key]

    def get_mapi_servers(self):
        return self.mapi_servers

    def add_wallet(self, wallet: 'Wallet') -> None:
        app_state.async_.spawn(self._wallet_jobs.put, ('add', wallet))

    def remove_wallet(self, wallet: 'Wallet') -> None:
        app_state.async_.spawn(self._wallet_jobs.put, ('remove', wallet))

    def chain(self):
        main_session = self.main_session()
        if main_session:
            return main_session.chain
        return app_state.headers.longest_chain()

    def get_local_height(self) -> int:
        chain = self.chain()
        # This can be called from network_dialog.py when there is no chain
        return chain.height if chain else 0

    def get_server_height(self) -> int:
        main_session = self.main_session()
        if main_session and main_session.tip:
            return main_session.tip.height
        return 0

    def backfill_headers_at_heights(self, heights: List[int]) -> None:
        app_state.async_.spawn(self._backfill_headers_at_heights, heights)

    async def _backfill_headers_at_heights(self, heights: List[int]) -> None:
        main_session = self.main_session()
        if main_session:
            await main_session._request_headers_at_heights(heights)
            self.trigger_callback('on_header_backfill')

    def set_server(self, server, auto_connect) -> None:
        app_state.config.set_key('server', server, True)
        if app_state.config.get('server') is server:
            app_state.config.set_key('auto_connect', auto_connect, False)
            app_state.async_.spawn(self._set_main_server, server, SwitchReason.user_set)

    def set_proxy(self, proxy) -> None:
        if str(proxy) == str(self.proxy):
            return
        app_state.config.set_key("proxy", proxy, False)
        # See if config accepted the update
        if str(app_state.config.get('proxy')) == str(proxy):
            self.proxy = proxy
            logger.info("Set proxy to %s", proxy)
            app_state.async_.spawn(self._restart_network)

    def sessions_by_chain(self):
        '''Return a map {chain: sessions} for each chain being followed by any session.'''
        result = defaultdict(list)
        for session in self.sessions:
            if session.chain:
                result[session.chain].append(session)
        return result

    def status(self) -> Dict[str, Any]:
        return {
            'server': str(self.main_server),
            'blockchain_height': self.get_local_height(),
            'server_height': self.get_server_height(),
            'spv_nodes': len(self.sessions),
            'connected': self.is_connected(),
            'auto_connect': self.auto_connect(),
        }

    # FIXME: this should be removed; its callers need to be fixed
    def request_and_wait(self, method, args):
        async def send_request():
            # We'll give 10 seconds for the wallet to reconnect..
            # NOTE(typing) We know `timeout_after` will be returning a context manager.
            async with timeout_after(10): # type: ignore
                session = await self._main_session()
            return await session.send_request(method, args)

        return app_state.async_.spawn_and_wait(send_request)

    def broadcast_transaction_and_wait(self, transaction: Transaction) -> str:
        return self.request_and_wait('blockchain.transaction.broadcast', [str(transaction)])

    def create_checkpoint(self, height: Optional[int]=None) -> None:
        '''Handy utility to dump a checkpoint for networks.py when preparing a new release.'''
        headers_obj = app_state.headers
        chain = headers_obj.longest_chain()
        if height is None:
            height = max(0, chain.height - 6)
        prev_work = headers_obj.chainwork_to_height(chain, height - 1)
        header_info = self.request_and_wait('blockchain.block.header', [height, height])
        header_hex = header_info['header']
        merkle_root = header_info['root']

        print(
            f"    CHECKPOINT = CheckPoint(bytes.fromhex(\n"
            f"        '{header_hex[:80]}'\n"
            f"        '{header_hex[80:]}'\n"
            f"    ), height={height}, prev_work={hex(prev_work)})\n"
            f"\n"
            f"    VERIFICATION_BLOCK_MERKLE_ROOT = (\n"
            f"        '{merkle_root}'\n"
            f"    )\n"
        )


JSON.register(SVServerState, SVServer, SVProxy)
