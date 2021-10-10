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
import datetime
from enum import IntEnum
from functools import partial
from ipaddress import IPv4Address, IPv6Address
import logging
import random
import re
import ssl
import time
from typing import Any, Callable, cast, Coroutine, Dict, Iterable, List, NamedTuple, Optional, \
    TYPE_CHECKING, TypedDict, Tuple, Union

from aiorpcx import (
    connect_rs, RPCSession, Notification, BatchError, RPCError, CancelledError, SOCKSError,
    TaskTimeout, TaskGroup, handler_invocation, Request, sleep, ignore_after, timeout_after,
    SOCKS4a, SOCKS5, SOCKSProxy, SOCKSUserAuth, NetAddress, NewlineFramer
)
from bitcoinx import BitcoinRegtest, Chain, CheckPoint, Coin, double_sha256, Header, Headers, \
    IncorrectBits, InsufficientPoW, MissingHeader, hash_to_hex_str, hex_str_to_hash, sha256
import certifi

from .app_state import app_state, attempt_exception_reporting
from .constants import API_SERVER_TYPES, NetworkServerType, TransactionImportFlag, TxFlags
from .i18n import _
from .logs import logs
from .network_support.api_server import NewServer, NewServerAPIContext
from .networks import Net
from .subscription import SubscriptionManager
from .transaction import Transaction
from .types import ElectrumXHistoryList, IndefiniteCredentialId, NetworkServerState, \
    ScriptHashSubscriptionEntry, ServerAccountKey
from .util import chunks, JSON, protocol_tuple, TriggeredCallbacks, version_string
from .version import PACKAGE_VERSION, PROTOCOL_MIN, PROTOCOL_MAX

if TYPE_CHECKING:
    from .wallet import AbstractAccount, Wallet


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


def broadcast_failure_reason(exception: Exception) -> str:
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


def _require_list(obj: Any) -> Union[Tuple[Any, ...], List[Any]]:
    assert isinstance(obj, (tuple, list))
    return obj


def _require_string(obj: Any) -> str:
    assert isinstance(obj, str)
    return obj


class HeadersResponse(TypedDict):
    count: int
    hex: str
    max: int
    root: str
    branch: List[str]


class HeaderProofResponse(TypedDict):
    branch: List[str]
    header: str
    root: str


class MerkleResponse(TypedDict):
    block_height: int
    merkle: List[str]
    pos: int


class HeaderResponse(TypedDict):
    hex: str
    height: int


def _root_from_proof(hash: bytes, branch: List[bytes], index: int) -> bytes:
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

    def __init__(self, reason: str, *, blacklist: bool=False) -> None:
        super().__init__(reason)
        self.blacklist = False


class SVServerState:
    '''The run-time state of an SVServer.'''

    def __init__(self) -> None:
        self.banner = ''
        self.donation_address = ''
        self.last_try = 0.
        self.last_good = 0.
        self.last_blacklisted = 0.
        self.retry_delay = 0
        self.is_disabled = False
        self.peers: List["SVServer"] = []

    def can_retry(self, now: float) -> bool:
        return not self.is_disabled and not self.is_blacklisted(now) and \
            self.last_try + self.retry_delay < now

    def is_blacklisted(self, now: float) -> bool:
        return self.last_blacklisted > now - ONE_DAY

    def to_json(self) -> Dict[str, int]:
        return {
            'last_try': int(self.last_try),
            'last_good': int(self.last_good),
            'last_blacklisted': int(self.last_blacklisted),
        }

    @classmethod
    def from_json(cls, dct: Dict[str, int]) -> "SVServerState":
        result = cls()
        for attr, value in dct.items():
            setattr(result, attr, value)
        return result

    def __str__(self) -> str:
        return str(self.to_json())


class SVServerKey(NamedTuple):
    host: str
    port: int
    protocol: str

    # Ensure that dictionary insertion is case insensitive.
    def __hash__(self) -> int:
        return hash((self.host.lower(), self.port, self.protocol.lower()))

    # Ensure that comparisons and dictionary lookups are case insensitive.
    def __eq__(self, other: object) -> bool:
        return isinstance(other, SVServerKey) \
            and self.host.lower() == other.host.lower() and self.port == other.port \
            and self.protocol.lower() == other.protocol.lower()

    def __ne__(self, other: object) -> bool:
        return not self.__eq__(other)


class SVServer:
    '''
    A smart wrapper around a (host, port, protocol) tuple.
    '''
    # The way SVServers are populated from config file is confusing. `JSON.register()` is called
    # for `SVServer` and when the config is deserialized, the specially serialised `SVServer`
    # entries are instantiated and in doing so they add themselves to the `all_servers` list.

    all_servers: Dict[SVServerKey, 'SVServer'] = {}
    _connection_task: Optional[asyncio.Task[None]] = None

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

    def remove(self) -> None:
        """
        Remove this server from the list of known servers.

        This will prevent the server from being saved into the config file, but keep in mind that
        missing servers that are bundled with ElectrumSV are restored on next startup.
        """
        del self.all_servers[self.key()]

    def _sslc(self) -> Optional[ssl.SSLContext]:
        if self.protocol != 's':
            return None
        # FIXME: implement certificate pinning like Electrum?
        return ssl.SSLContext(ssl.PROTOCOL_TLS)

    def _connector(self, session_factory: partial["SVSession"], proxy: Optional["SVProxy"]) \
            -> connect_rs:
        return connect_rs(self.host, self.port, proxy=proxy, session_factory=session_factory,
                          ssl=self._sslc())

    def disconnected(self) -> bool:
        return self._connection_task is None or self._connection_task.done()

    def add_disconnection_callback(self, callback: Callable[[asyncio.Future[None]], None]) -> bool:
        if self._connection_task is not None and not self._connection_task.done():
            self._connection_task.add_done_callback(callback)
            return True
        return False

    def disconnect(self) -> None:
        if self._connection_task is not None:
            self._connection_task.cancel()
            self._connection_task = None

    def _logger(self, n: str) -> logging.Logger:
        logger_name = f'[{self.host}:{self.port} {self.protocol_text()} #{n}]'
        return logs.get_logger(logger_name)

    def to_json(self) -> Tuple[str, int, str, SVServerState]:
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
        try:
            async with TaskGroup() as group:
                self._connection_task = await group.spawn(self._connect, network, logger_name)
        finally:
            self._connection_task = None

    async def _connect(self, network: 'Network', logger_name: str) -> None:
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


# NOTE(typing) No typing for this base class, so ignore..
class SVUserAuth(SOCKSUserAuth): # type: ignore
    def __repr__(self) -> str:
        # So its safe in logs, etc.  Also used in proxy comparisons.
        hash_str = sha256(str((self.username, self.password)).encode())[:8].hex()
        return f'{self.__class__.__name__}({hash_str})'


# NOTE(typing) No typing for this base class, so ignore..
class SVProxy(SOCKSProxy): # type: ignore
    '''Encapsulates a SOCKS proxy.'''

    kinds = {'SOCKS4' : SOCKS4a, 'SOCKS5': SOCKS5}

    auth: SOCKSUserAuth

    def __init__(self, address: Union[NetAddress, str, Tuple[str, str]], kind: str,
            auth: Optional[Union[SOCKSUserAuth, List[str]]]=None) -> None:
        protocol = self.kinds.get(kind.upper())
        if not protocol:
            raise ValueError(f'invalid proxy kind: {kind}')
        # This class is serialised using `util.JSON` hooks, this is not possible for `SVUserAuth`
        # as that is naturally serialisable via `json.dumps` and the hook is not called.
        if isinstance(auth, list):
            auth = SVUserAuth(*auth)
        super().__init__(address, protocol, auth)

    def to_json(self) -> Tuple[str, str, List[str]]:
        return (str(self.address), self.kind(), list(self.auth))

    @classmethod
    def from_json(cls, obj: Tuple[str, str, List[str]]) -> "SVProxy":
        return cls(*obj)

    @classmethod
    def from_string(cls, obj: str) -> Optional["SVProxy"]:
        # Backwards compatibility
        try:
            kind, host, port, username, password = obj.split(':', 5)
            return cls((host, port), kind, SVUserAuth(username, password))
        except Exception:
            return None

    def kind(self) -> str:
        return 'SOCKS4' if self.protocol is SOCKS4a else 'SOCKS5'

    def host(self) -> Union[IPv4Address, IPv6Address]:
        return cast(Union[IPv4Address, IPv6Address], self.address.host)

    def port(self) -> int:
        return cast(int, self.address.port)

    def username(self) -> str:
        return cast(str, self.auth.username) if self.auth else ''

    def password(self) -> str:
        return cast(str, self.auth.password) if self.auth else ''

    def __str__(self) -> str:
        return ', '.join((repr(self.address), self.kind(), repr(self.auth)))


# NOTE(typing) base class lacks typing.
class SVSession(RPCSession): # type: ignore

    ca_path = certifi.where()
    _connecting_tips: Dict[bytes, asyncio.Event] = {}
    _need_checkpoint_headers = True
    _script_hash_ids: Dict[bytes, int] = {}
    _have_made_initial_script_hash_subscriptions = False

    def __init__(self, network: "Network", server: SVServer, logger: logging.Logger,
            *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._handlers: Dict[str, Callable[..., Coroutine[Any, Any, None]]] = {}
        self._network = network
        self._closed_event = app_state.async_.event()
        # These attributes are intended to part of the external API
        self.chain: Optional[Chain] = None
        self.logger = logger
        self.server = server
        self.tip: Optional[Header] = None
        self.ptuple: Tuple[int, ...] = (0, )

    def set_throttled(self, flag: bool) -> None:
        if flag:
            RPCSession.recalibrate_count = 30
        else:
            RPCSession.recalibrate_count = 10000000000

    def get_current_outgoing_concurrency_target(self) -> int:
        return cast(int, self._outgoing_concurrency.max_concurrent)

    def default_framer(self) -> NewlineFramer:
        max_size = app_state.electrumx_message_size_limit()*1024*1024
        return NewlineFramer(max_size=max_size)

    @classmethod
    def _required_checkpoint_headers(cls) -> Tuple[int, int]:
        '''Returns (start_height, count).  The range of headers needed for the DAA so that all
        post-checkpoint headers can have their difficulty verified.
        '''
        if cls._need_checkpoint_headers:
            headers_obj = cast(Headers, app_state.headers)
            chain = headers_obj.longest_chain()
            cp_height = cast(CheckPoint, headers_obj.checkpoint).height
            if cp_height == 0:
                cls._need_checkpoint_headers = False
            else:
                try:
                    for height in range(cp_height - 146, cp_height):
                        headers_obj.header_at_height(chain, height)
                    cls._need_checkpoint_headers = False
                except MissingHeader:
                    return height, cp_height - height
        return 0, 0

    @classmethod
    def _connect_header(cls, height: int, raw_header: bytes) -> Tuple[Header, Chain]:
        '''It is assumed that if height is <= the checkpoint height then the header has
        been checked for validity.
        '''
        headers_obj = cast(Headers, app_state.headers)
        checkpoint = cast(CheckPoint, headers_obj.checkpoint)

        if height <= checkpoint.height:
            headers_obj.set_one(height, raw_header)
            headers_obj.flush()
            header = Net.COIN.deserialized_header(raw_header, height)
            return header, headers_obj.longest_chain()
        else:
            return cast(Tuple[Header, Chain], headers_obj.connect(raw_header))

    @classmethod
    def _connect_chunk(cls, start_height: int, raw_chunk: bytes) -> Chain:
        '''It is assumed that if the last header of the raw chunk is before the checkpoint height
        then it has been checked for validity.
        '''
        headers_obj = cast(Headers, app_state.headers)
        checkpoint = cast(CheckPoint, headers_obj.checkpoint)
        coin = cast(Coin, headers_obj.coin)
        end_height = start_height + len(raw_chunk) // HEADER_SIZE

        def extract_header(height: int) -> bytes:
            start = (height - start_height) * HEADER_SIZE
            return raw_chunk[start: start + HEADER_SIZE]

        def verify_chunk_contiguous_and_set(next_raw_header: bytes, to_height: int) -> None:
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

    async def _negotiate_protocol(self) -> None:
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

    async def _get_checkpoint_headers(self) -> None:
        '''Raises: RPCError, TaskTimeout'''
        while True:
            start_height, header_count = self._required_checkpoint_headers()
            if not header_count:
                break
            logger.info("%d checkpoint headers needed", header_count)
            await self._request_chunk(start_height, header_count)

    async def _request_chunk(self, start_height: int, header_count: int) -> int:
        '''Returns the greatest height successfully connected (might be lower than expected
        because of a small server response).

        Raises: RPCError, TaskTimeout, DisconnectSessionError'''
        self.logger.info("requesting %d headers from height %d", header_count, start_height)
        method = 'blockchain.block.headers'
        assert app_state.headers is not None
        cp_height = cast(int, app_state.headers.checkpoint.height)
        if start_height + header_count >= cp_height:
            cp_height = 0

        try:
            result = cast(HeadersResponse,
                await self.send_request(method, (start_height, header_count, cp_height)))

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

    async def _subscribe_headers(self) -> None:
        '''Raises: RPCError, TaskTimeout, DisconnectSessionError'''
        self._handlers[HEADERS_SUBSCRIBE] = self._on_new_tip
        tip = cast(HeaderResponse, await self.send_request(HEADERS_SUBSCRIBE))
        await self._on_new_tip(tip)

    # NOTE(typing) Override the default aiorpcx typing for this variable.
    last_send: float

    def _secs_to_next_ping(self) -> float:
        return self.last_send + 300.0 - time.time()

    async def _ping_loop(self) -> None:
        '''Raises: RPCError, TaskTimeout'''
        method = 'server.ping'
        while True:
            await sleep(self._secs_to_next_ping())
            if self._secs_to_next_ping() < 1:
                self.logger.debug("sending %s", method)
                await self.send_request(method)

    def _check_header_proof(self, hex_root: str, branch: List[bytes], raw_header: bytes,
            header_height: int) -> None:
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

    async def _on_new_tip(self, json_tip: HeaderResponse) -> None:
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

    async def _catch_up_to_tip_throttled(self, tip: Header) -> None:
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

    async def _catch_up_to_tip(self, tip: Header) -> None:
        '''Raises: DisconnectSessionError, BatchError, TaskTimeout'''
        headers_obj = cast(Headers, app_state.headers)
        cp_height = cast(int, headers_obj.checkpoint.height)
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
        status = cast(str, await self.send_request(SCRIPTHASH_SUBSCRIBE, [script_hash_hex]))
        await self._on_queue_status_changed(script_hash_hex, status)

    async def _unsubscribe_from_script_hash(self, script_hash: str) -> bool:
        return cast(bool, await self.send_request(SCRIPTHASH_UNSUBSCRIBE, [script_hash]))

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

        await self._network.subscriptions.on_script_hash_history(subscription_id,
            script_hash_bytes, result)

    async def _main_server_batch(self) -> None:
        '''Raises: DisconnectSessionError, BatchError, TaskTimeout'''
        async with timeout_after(10):
            async with self.send_batch(raise_errors=True) as batch:
                batch.add_request('server.banner')
                batch.add_request('server.donation_address')
                batch.add_request('server.peers.subscribe')
        batch_results = cast(Tuple[Any, Any, Any], batch.results)
        server = self.server
        try:
            server.state.banner = _require_string(batch_results[0])
            server.state.donation_address = _require_string(batch_results[1])
            server.state.peers = self._parse_peers_subscribe(batch_results[2])
            self._network.trigger_callback('banner')
        except AssertionError as e:
            raise DisconnectSessionError(f'main server requests bad batch response: {e}')

    def _parse_peers_subscribe(self, result: Any) -> List[SVServer]:
        peers: List[SVServer] = []
        for host_details in _require_list(result):
            host_details = cast(Tuple[Any, str, List[str]], _require_list(host_details))
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

    async def _request_headers_at_heights(self, heights: List[int]) -> int:
        '''Requests the headers as a batch and connects them, lowest height first.

        Return the greatest connected height (-1 if none connected).
        Raises: DisconnectSessionError, BatchError, TaskTimeout
        '''
        good_height = -1
        async def _request_header_batch(batch_heights: List[int]) -> None:
            nonlocal good_height

            self.logger.debug("requesting %d headers at heights %s", len(batch_heights),
                batch_heights)
            async with timeout_after(10):
                async with self.send_batch(raise_errors=True) as batch:
                    for height in batch_heights:
                        batch.add_request(method,
                                          (height, cp_height if height <= cp_height else 0))

            batch_results = cast(Union[str, HeaderProofResponse], batch.results)
            try:
                for result, height in zip(batch_results, batch_heights):
                    if height <= cp_height:
                        cp_result = cast(HeaderProofResponse, result)
                        hex_root = cp_result['root']
                        branch = [hex_str_to_hash(item) for item in cp_result['branch']]
                        raw_header = bytes.fromhex(cp_result['header'])
                        self._check_header_proof(hex_root, branch, raw_header, height)
                    else:
                        raw_header = bytes.fromhex(result)
                    _header, self.chain = self._connect_header(height, raw_header)
                    good_height = height
            except MissingHeader:
                hex_str = hash_to_hex_str(Net.COIN.header_hash(raw_header))
                self.logger.info("failed to connect at height %d, hash %s last good %d",
                    height, hex_str, good_height)
            except (AssertionError, KeyError, TypeError, ValueError) as e:
                raise DisconnectSessionError(f'bad {method} response: {e}')

        heights = sorted(set(heights))
        cp_height = Net.CHECKPOINT.height
        method = 'blockchain.block.header'
        min_good_height = max((height for height in heights if height <= cp_height), default=-1)
        for chunk in chunks(heights, 100):
            await _request_header_batch(chunk)
        if good_height < min_good_height:
            raise DisconnectSessionError(f'cannot connect to checkpoint', blacklist=True)
        return good_height

    # What gets passed here?
    async def handle_request(self, request: Union[Request, Notification]) -> None:
        if isinstance(request, Notification):
            handler = self._handlers.get(request.method)
        else:
            handler = None
        coro = handler_invocation(handler, request)()
        await coro

    async def connection_lost(self) -> None:
        await super().connection_lost()
        self._closed_event.set()

    #
    # API exposed to the rest of this file
    #

    async def disconnect(self, reason: str, *, blacklist: bool=False) -> None:
        if blacklist:
            self.server.state.last_blacklisted = time.time()
            self.logger.error("disconnecting and blacklisting: %s", reason)
        else:
            self.logger.error("disconnecting: %s", reason)
        await self.close()

    async def run(self) -> None:
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

    async def headers_at_heights(self, heights: Iterable[int]) -> Dict[int, Header]:
        '''Raises: MissingHeader, DisconnectSessionError, BatchError, TaskTimeout'''
        result = {}
        missing = []
        header_at_height = cast(Headers, app_state.headers).header_at_height
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

    async def request_tx(self, tx_id: str) -> str:
        '''Raises: RPCError, TaskTimeout'''
        return cast(str, await self.send_request('blockchain.transaction.get', [tx_id]))

    async def request_proof(self, tx_id: str, tx_height: int) -> MerkleResponse:
        '''Raises: RPCError, TaskTimeout'''
        return cast(MerkleResponse, await self.send_request(REQUEST_MERKLE_PROOF,
            (tx_id, tx_height)))

    async def request_history(self, script_hash_hex: str) -> ElectrumXHistoryList:
        '''Raises: RPCError, TaskTimeout'''
        return cast(ElectrumXHistoryList,
            await self.send_request(SCRIPTHASH_HISTORY, [script_hash_hex]))

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
    _main_task_active = False

    def __init__(self) -> None:
        TriggeredCallbacks.__init__(self)

        app_state.read_headers()

        self.subscriptions = SubscriptionManager()

        # Sessions
        self.sessions: List[SVSession] = []
        self._chosen_servers: set[SVServer] = set()
        self.main_server: Optional[SVServer] = None
        self.proxy: Optional[SVProxy] = None

        # The usable set of API servers both globally known by the application and also
        # per-wallet/account servers from each wallet database.
        self._api_servers: Dict[ServerAccountKey, NewServer] = {}
        # Track the application API servers from the config and add them to the usable set.
        self._api_servers_config: Dict[NetworkServerType, List[Dict[str, Any]]] = {
            server_type: [] for server_type in API_SERVER_TYPES
        }
        self._read_config_api_server_mapi()

        # Events
        async_ = app_state.async_
        self.sessions_changed_event = async_.event()
        self.check_main_chain_event = async_.event()
        self.stop_network_event = async_.event()
        self.shutdown_complete_event = async_.event()

        # Add an wallet, remove an wallet, or redo all wallet verifications
        self._wallet_jobs = async_.queue()

        # Feed pub-sub notifications to currently active SVSession for processing
        self._on_status_queue = async_.queue()

        self.future = async_.spawn(self._main_task_loop)

        self.subscriptions.set_script_hash_callbacks(
            self._on_subscribe_script_hashes, self._on_unsubscribe_script_hashes)

    def _read_config_api_server_mapi(self) -> None:
        mapi_servers = cast(List[Dict[str, Any]], app_state.config.get("mapi_servers", []))
        if mapi_servers:
            logger.info("read %d merchant api servers from config file", len(mapi_servers))

        servers_by_uri = { mapi_server['url']: mapi_server for mapi_server in mapi_servers }
        for mapi_server in Net.DEFAULT_MAPI_SERVERS:
            server = servers_by_uri.get(mapi_server['url'], None)
            if server is None:
                server = mapi_server.copy()
                server["modified_date"] = server["static_data_date"]
                mapi_servers.append(server)
            self._migrate_config_mapi_entry(server)

        # Register the MAPI server for visibility and maybe even usage. We pass in the reference
        # to the config entry dictionary, which will be saved via `_api_servers_config`.
        for mapi_server in mapi_servers:
            server_key = ServerAccountKey(mapi_server["url"], NetworkServerType.MERCHANT_API)
            self._api_servers[server_key] = self._create_config_api_server(server_key, mapi_server)

        # This is the collection of application level servers and it is primarily used to group
        # them for persistence.
        self._api_servers_config[NetworkServerType.MERCHANT_API] = mapi_servers

    def _migrate_config_mapi_entry(self, server: Dict[str, Any]) -> None:
        ## Ensure all the default field values are present if they are not already.
        server.setdefault("api_key", "")
        # Whether the API key is supported for the given server from entry presence.
        server.setdefault("api_key_supported", "api_key_required" in server)
        # All the default MAPI servers are enabled for all wallets out of the box.
        server.setdefault("enabled_for_all_wallets", True)
        # When we were last able to connect, and when we last tried to connect.
        server.setdefault("last_good", 0.0)
        server.setdefault("last_try", 0.0)
        # If we request an anonymous fee quote for this server, keep the last one.
        server.setdefault("anonymous_fee_quote", {})

    async def _main_task_loop(self) -> None:
        self._main_task_active = True
        iterations = 0
        try:
            while self._main_task_active:
                if iterations > 0:
                    logger.debug("Restarting main task, attempt %d", iterations)
                await self._main_task()
                iterations += 1
        finally:
            logger.debug("Network main task loop exiting.")
            self.shutdown_complete_event.set()
            app_state.config.set_key('servers', list(SVServer.all_servers.values()), True)
            app_state.config.set_key('mapi_servers', self.get_config_mapi_servers(), True)

    async def _main_task(self) -> None:
        # self._cevent = app_state.async_.event() # TODO remove
        group = TaskGroup()
        try:
            async with group:
                await group.spawn(self._start_network, group)
                await group.spawn(self._monitor_lagging_sessions)
                await group.spawn(self._monitor_main_chain)
                await group.spawn(self._initial_script_hash_status_subscriptions, group)
                await group.spawn(self._monitor_script_hash_status_subscriptions, group)
                await group.spawn(self._monitor_wallets, group)
                # self._ctask = await group.spawn(self._cancellable_task) # TODO remove
        finally:
            logger.debug("Network main task exiting")
            # NOTE(exception-reporting) We only try reporting the first exception for now, we do
            # not really expect more than one and it might become spammy if there are many.
            # NOTE(network-exit-bug) We have a problem where the network main task exits because
            # presumably an exception happens in a task, or a task is cancelled by something
            # unknown and this is caught by the `TaskGroup` and causes the cancellation of
            # all the tasks in it (and previously the network main task to exit).
            reported_one_exception = False
            for exc_idx, exc in enumerate(group.exceptions):
                if exc is not None:
                    if not isinstance(exc, CancelledError) and not reported_one_exception:
                        reported_one_exception = True
                        attempt_exception_reporting(type(exc), exc, exc.__traceback__)
                    # Do not log `CancelledError` if we are exiting the network as it is normal.
                    if not self._main_task_active and isinstance(exc, CancelledError):
                        continue
                    # Otherwise log it (in addition to exceptions) because this is possibly an
                    # erroneous cancellation and we want to see where they all came from (this
                    # might not even be good enough and the real problem may be in sub-taskgroups.
                    logger.exception("Exception in task %d", exc_idx,
                        exc_info=(type(exc), exc, exc.__traceback__))

    # async def _cancellable_task(self) -> None: # TODO remove
    #     await self._cevent.wait()
    #     raise Exception("zzzz")

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
                assert self.main_server is not None
                server = await self._random_server(self.main_server.protocol)
            assert server is not None

            self._chosen_servers.add(server)
            try:
                await server.connect(self, str(n))
            except (OSError, SOCKSError) as e:
                logger.error("%s connection error: %s", server, str(e))
            finally:
                self._chosen_servers.remove(server)

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
            async with ignore_after(20):
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
        # Disconnect the old main session, if any, in order to lose scripthash
        # subscriptions.
        if old_main_session:
            if reason == SwitchReason.user_set:
                old_main_session.server.state.retry_delay = 0
            await old_main_session.close()
        self.trigger_callback('status')

    def add_electrumx_server(self, server_key: SVServerKey) \
            -> None:
        """
        Add a new electrumx server.
        """
        if server_key in SVServer.all_servers:
            raise KeyError("server already exists")

        if server_key.protocol not in 'st':
            raise ValueError(f'unknown protocol: {server_key.protocol}')

        # This will register the server and make it available to the server connection logic
        # to make use of. The server will also be persisted when the network shuts down.
        SVServer.unique(server_key.host, server_key.port, server_key.protocol)

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
        callback_pending = False
        try:
            if not server.disconnected():
                def disconnection_callback(_future: asyncio.Future[None]) -> None:
                    assert server is not None
                    server.state.is_disabled = was_disabled
                callback_pending = server.add_disconnection_callback(disconnection_callback)
                server.disconnect()

            server.update(updated_key)
        finally:
            if not callback_pending:
                server.state.is_disabled = was_disabled

    def update_electrumx_server(self, existing_key: SVServerKey, updated_key: SVServerKey) \
            -> None:
        return app_state.async_.spawn_and_wait(self.update_electrumx_server_async,
            existing_key, updated_key)

    async def delete_electrumx_server_async(self, existing_key: SVServerKey,
            callback: Optional[Callable[[], None]]=None) -> None:
        server = SVServer.all_servers.get(existing_key)
        if server is None:
            raise KeyError("server does not exist")

        def on_disconnection_completed(*_: Any) -> None:
            assert server is not None
            server.remove()
            if callback is not None:
                callback()

        server.state.is_disabled = True
        callback_pending = False
        if server.add_disconnection_callback(on_disconnection_completed):
            callback_pending = True
        server.disconnect()
        if not callback_pending:
            on_disconnection_completed()

    def delete_electrumx_server(self, existing_key: SVServerKey,
            callback: Optional[Callable[[], None]]=None) -> None:
        app_state.async_.spawn(self.delete_electrumx_server_async, existing_key, callback)

    def _read_config_electrumx(self) -> Tuple[SVServer, Optional[SVProxy]]:
        # Remove obsolete key
        config = app_state.config
        config.set_key('server_blacklist', None)
        # The way SVServers are populated from config file is confusing. JSON.register() is called
        # for SVServer and when the config is deserialized, the specially serialised SVServer
        # entries are instantiated and in doing so they add themselves to the `all_servers` list.
        logger.info('Read %d electrumx servers from config file', len(SVServer.all_servers))
        # Add default servers if not present. If we add the ability for users to delete servers
        # and they want to delete default serves, then this will override that.
        for host, data in Net.DEFAULT_SERVERS.items():
            for protocol in 'st':
                if protocol in data:
                    SVServer.unique(host, data[protocol], protocol)

        main_server = config.get('server', None)
        if isinstance(main_server, str):
            main_server = SVServer.from_string(main_server)
            config.set_key('server', main_server, True)
        if not isinstance(main_server, SVServer):
            logger.info('choosing an SSL server randomly; none in config')
            # TODO We need a better server selection mechanism where if we choose the secure
            #   version it falls back to the insecure version if there is one specified.
            if Net.COIN is BitcoinRegtest:
                main_server = self._random_server_nowait('t')
            else:
                main_server = self._random_server_nowait('s')
            if not main_server:
                raise RuntimeError('no servers available')

        proxy = config.get('proxy', None)
        if isinstance(proxy, str):
            proxy = SVProxy.from_string(proxy)

        logger.info("main server: %s, proxy: %s", main_server, proxy)
        return main_server, proxy

    async def _request_transactions(self, wallet: "Wallet", missing_hashes: List[bytes]) -> bool:
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
                assert task is not None
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
                        import_flags=TransactionImportFlag.EXTERNAL)
        return had_timeout

    def _available_servers(self, protocol: str) -> List[SVServer]:
        now = time.time()
        unchosen = set(SVServer.all_servers.values()).difference(self._chosen_servers)
        return [server for server in unchosen
                if server.protocol == protocol and server.state.can_retry(now)]

    def _random_server_nowait(self, protocol: str) -> Optional[SVServer]:
        servers = self._available_servers(protocol)
        return random.choice(servers) if servers else None

    async def _random_server(self, protocol: str) -> SVServer:
        while True:
            server = self._random_server_nowait(protocol)
            if server:
                return server
            await sleep(10)

    async def _request_proofs(self, wallet: "Wallet", wanted_map: Dict[bytes, int]) -> bool:
        had_timeout = False
        session = await self._main_session()
        session.logger.debug("requesting %d proofs", len(wanted_map))
        async with TaskGroup() as group:
            tasks: Dict[asyncio.Task[MerkleResponse], Tuple[bytes, str]] = {}
            for tx_hash, tx_height in wanted_map.items():
                tx_id = hash_to_hex_str(tx_hash)
                tasks[await group.spawn(session.request_proof(tx_id, tx_height))] = (tx_hash,
                    tx_id)
            headers = await session.headers_at_heights(wanted_map.values())

            while tasks:
                task = await group.next_done()
                assert task is not None
                tx_hash, tx_id = tasks.pop(task)
                block_height = wanted_map[tx_hash]
                try:
                    result = cast(MerkleResponse, task.result())
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
            entries = self.subscriptions.read_script_hashes()
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
            await session._on_script_hash_status_changed(script_hash, status)

    async def _monitor_txs(self, wallet: "Wallet") -> None:
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

    async def _maintain_wallet(self, wallet: "Wallet") -> None:
        '''Put all tasks for a single wallet in a group so they can be cancelled together.'''
        logger.info('maintaining wallet %s', wallet)
        with suppress(CancelledError):
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

    async def _main_session(self) -> SVSession:
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

    async def session_established(self, session: SVSession) -> bool:
        self.sessions.append(session)
        self.sessions_changed_event.set()
        self.sessions_changed_event.clear()
        self.trigger_callback('sessions')
        if session.server is self.main_server:
            self.trigger_callback('status')
            return True
        return False

    async def session_closed(self, session: SVSession) -> None:
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
        self._main_task_active = False
        self.future.cancel()
        await self.shutdown_complete_event.wait()
        assert not self.sessions
        self.subscriptions.stop()
        logger.warning('stopped')

    def auto_connect(self) -> bool:
        return app_state.config.get_explicit_type(bool, 'auto_connect', True)

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

    def get_config_mapi_servers(self) -> List[Dict[str, Any]]:
        """
        Update the mapi server config entries and return them.

        This will pull in the live server state.
        """
        for config in self._api_servers_config[NetworkServerType.MERCHANT_API]:
            server_key = ServerAccountKey(config["url"], NetworkServerType.MERCHANT_API)
            server = self._api_servers[server_key]
            key_state = server.api_key_state[server.config_credential_id]
            config["last_good"] = key_state.last_good
            config["last_try"] = key_state.last_try
            if server.config_credential_id is None:
                config["anonymous_fee_quote"] = key_state.last_fee_quote_response
            else:
                config["anonymous_fee_quote"] = None
        return self._api_servers_config[NetworkServerType.MERCHANT_API]

    def create_config_api_server(self, server_type: NetworkServerType,
            server_data: Dict[str, Any]) -> None:
        """
        Register a new application-level API server entry.

        This will set up the standard default fields, so it is not necessary for any caller to
        provide a 100% complete entry.
        """
        server_url = cast(str, server_data["url"])
        assert server_url not in [ d["url"] for d in self._api_servers_config[server_type] ]
        if server_type == NetworkServerType.MERCHANT_API:
            self._migrate_config_mapi_entry(server_data)
        self._api_servers_config[server_type].append(server_data)

        server_key = ServerAccountKey(server_url, server_type)
        if server_key in self._api_servers:
            return
        self._api_servers[server_key] = self._create_config_api_server(server_key)

    def update_config_api_server(self, server_url: str, server_type: NetworkServerType,
            update_data: Dict[str, Any]) -> None:
        """
        Update fields in an existing application-level API server entry.

        This just overwrites existing fields and can only be used for limited updates.
        """
        update_data["modified_date"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        for config in self._api_servers_config[server_type]:
            if config["url"] == server_url:
                server_key = ServerAccountKey(server_url, server_type)
                server = self._api_servers[server_key]
                server.on_pending_config_change(update_data)
                config.update(update_data)
                break
        else:
            self.create_config_api_server(server_type, update_data)

    def delete_config_api_server(self, server_url: str, server_type: NetworkServerType) -> None:
        for config_index, config in enumerate(self._api_servers_config[server_type]):
            if config["url"] == server_url:
                del self._api_servers_config[server_type][config_index]
                del self._api_servers[ServerAccountKey(server_url, server_type)]
                break
        else:
            raise KeyError(f"Server '{server_url}' does not exist")

    def get_api_servers(self) -> Dict[ServerAccountKey, NewServer]:
        # These are all the available API servers registered within the application.
        return self._api_servers

    def get_api_servers_for_account(self, account: "AbstractAccount") \
            -> List[Tuple[NewServer, Optional[IndefiniteCredentialId]]]:
        wallet = account.get_wallet()
        client_key = NewServerAPIContext(wallet.get_storage_path(), account.get_id())

        results: List[Tuple[NewServer, Optional[IndefiniteCredentialId]]] = []
        for api_server in self._api_servers.values():
            have_credential, credential_id = api_server.get_credential_id(client_key)
            # TODO(API) What about putting the client api context in the result.
            if have_credential:
                results.append((api_server, credential_id))
        return results

    def is_server_disabled(self, url: str, server_type: NetworkServerType) -> bool:
        """
        Whether the given server is configured to be unusable by anything.
        """
        if server_type == NetworkServerType.ELECTRUMX:
            return False
        return self._api_servers[ServerAccountKey(url, server_type)].is_unusable()

    def _create_config_api_server(self, server_key: ServerAccountKey,
            config: Optional[Dict[str,Any]]=None, allow_no_config: bool=False) -> NewServer:
        if config is None:
            # The config entry should exist except when an external wallet database is brought
            # to this installation and loaded, with unknown servers in it.
            for iter_config in self._api_servers_config[server_key.server_type]:
                if iter_config["url"] == server_key.url:
                    config = iter_config
                    break
            else:
                if not allow_no_config:
                    raise KeyError(f"Server config not found {server_key.url}")
        return NewServer(server_key.url, server_key.server_type, config)

    def _register_api_servers_for_wallet(self, wallet: "Wallet") -> None:
        """ For a newly loaded wallet, set up it's API server usage. This will """
        rows = wallet.read_network_servers_with_credentials()

        wallet_path = wallet.get_storage_path()
        for row in rows:
            if row.key.server_type not in API_SERVER_TYPES:
                continue
            # If the server does not exist already it is not one known globally to the application.
            server_key = row.key.to_server_key()
            if server_key not in self._api_servers:
                self._api_servers[server_key] = self._create_config_api_server(server_key,
                    allow_no_config=True)
            server = self._api_servers[server_key]
            server.set_wallet_usage(wallet_path, row)

    def _unregister_all_api_servers_for_wallet(self, wallet: "Wallet") -> List[NetworkServerState]:
        """ Unregister a specific wallet from all API servers. We do this when a wallet has been
            unloaded. """
        wallet_path = wallet.get_storage_path()
        updated_states: List[NetworkServerState] = []
        for server_key, server in list(self._api_servers.items()):
            updated_states.extend(server.unregister_wallet(wallet_path))
            # TODO(rt12) Why are we deleting unused servers from this data structure?
            if server.is_unused():
                del self._api_servers[server_key]
        return updated_states

    def update_api_servers_for_wallet(self,
            wallet: "Wallet", added_keys: List[NetworkServerState],
            updated_keys: List[NetworkServerState], deleted_keys: List[ServerAccountKey]) -> None:
        """
        This is called by the wallet to update the wallet usage of added, updated or removed
        api servers
        """
        wallet_path = wallet.get_storage_path()
        # We know updated servers will not have changed their type or url, so we do not need
        # to do anything with the accounts at this point. But we do need to have observed the flags
        # of servers for enabling/disabling.
        for row in added_keys + updated_keys:
            server = self._api_servers[row.key.to_server_key()]
            server.set_wallet_usage(wallet_path, row)

        for specific_server_key in deleted_keys:
            server = self._api_servers[specific_server_key.to_server_key()]
            server.remove_wallet_usage(wallet_path, specific_server_key)

    def add_wallet(self, wallet: "Wallet") -> None:
        """ This wallet has been loaded and is now using this network. """
        self._register_api_servers_for_wallet(wallet)
        app_state.async_.spawn(self._wallet_jobs.put, ('add', wallet))

    def remove_wallet(self, wallet: "Wallet") -> List[NetworkServerState]:
        """ This wallet has been unloaded and is no longer using this network. """
        updated_states = self._unregister_all_api_servers_for_wallet(wallet)
        app_state.async_.spawn(self._wallet_jobs.put, ('remove', wallet))
        return updated_states

    def chain(self) -> Optional[Chain]:
        main_session = self.main_session()
        if main_session:
            return main_session.chain
        return cast(Headers, app_state.headers).longest_chain()

    def get_local_height(self) -> int:
        chain = self.chain()
        # This can be called from network_dialog.py when there is no chain
        return cast(int, chain.height) if chain else 0

    def get_server_height(self) -> int:
        main_session = self.main_session()
        if main_session and main_session.tip:
            return cast(int, main_session.tip.height)
        return 0

    def backfill_headers_at_heights(self, heights: List[int]) -> None:
        app_state.async_.spawn(self._backfill_headers_at_heights, heights)

    async def _backfill_headers_at_heights(self, heights: List[int]) -> None:
        main_session = self.main_session()
        if main_session:
            await main_session._request_headers_at_heights(heights)
            self.trigger_callback('on_header_backfill')

    def set_server(self, server: SVServer, auto_connect: bool) -> None:
        config = app_state.config
        config.set_key('server', server, True)
        if config.get('server') is server:
            config.set_key('auto_connect', auto_connect, False)
            app_state.async_.spawn(self._set_main_server, server,
                SwitchReason.user_set)

    def set_proxy(self, proxy: Optional[SVProxy]) -> None:
        if str(proxy) == str(self.proxy):
            return
        app_state.config.set_key("proxy", proxy, False)
        # See if config accepted the update
        if str(app_state.config.get('proxy')) == str(proxy):
            self.proxy = proxy
            logger.info("Set proxy to %s", proxy)
            app_state.async_.spawn(self._restart_network)

    def sessions_by_chain(self) -> Dict[Chain, List[SVSession]]:
        '''Return a map {chain: sessions} for each chain being followed by any session.'''
        result: Dict[Chain, List[SVSession]] = defaultdict(list)
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
    def request_and_wait(self, method: str, args: Any) -> Any:
        async def send_request() -> Any:
            # We'll give 10 seconds for the wallet to reconnect..
            async with timeout_after(10):
                session = await self._main_session()
            return await session.send_request(method, args)

        return app_state.async_.spawn_and_wait(send_request)

    def broadcast_transaction_and_wait(self, transaction: Transaction) -> str:
        return cast(str,
            self.request_and_wait('blockchain.transaction.broadcast', [str(transaction)]))

    def create_checkpoint(self, height: Optional[int]=None) -> None:
        '''Handy utility to dump a checkpoint for networks.py when preparing a new release.'''
        headers_obj = cast(Headers, app_state.headers)
        chain = headers_obj.longest_chain()
        if height is None:
            height = max(0, chain.height - 6)
        prev_work = headers_obj.chainwork_to_height(chain, height - 1)
        header_info = cast(HeaderProofResponse,
            self.request_and_wait('blockchain.block.header', [height, height]))
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
