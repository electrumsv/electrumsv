import asyncio
import concurrent.futures
import dataclasses
import http
from io import BytesIO
from typing import AsyncIterable, cast, Optional

import aiohttp
import bitcoinx
from bitcoinx import (Chain, deserialized_header, double_sha256,
                      hash_to_hex_str, Header)

from ..app_state import app_state
from ..exceptions import ServiceUnavailableError
from ..logs import logs
from ..types import ServerAccountKey
from .exceptions import HeaderNotFoundError, HeaderResponseError
from .types import TipResponse

logger = logs.get_logger("header-client")


@dataclasses.dataclass
class ServerConnectivityMetadata:
    last_try = 0.0
    last_good = 0.0

    consecutive_failed_attempts = 0

    retry_delay = 0
    last_blacklisted = 0.0
    is_disabled = False



@dataclasses.dataclass
class HeaderServerState:
    server_key: ServerAccountKey
    future: concurrent.futures.Future[None]

    chain: Chain | None = None
    tip_header: Header | None = None
    synchronisation_data: tuple[int, int] | None = None

    connection_event: asyncio.Event = dataclasses.field(default_factory=asyncio.Event)
    synchronisation_update_event: asyncio.Event = dataclasses.field(default_factory=asyncio.Event)


async def get_batched_headers_by_height_async(server_state: HeaderServerState,
        session: aiohttp.ClientSession, from_height: int, count: Optional[int]=None) -> bytes:
    url = f"{server_state.server_key.url}api/v1/headers/by-height?height={from_height}"
    if count:
        url += f"&count={count}"
    headers = {"Accept": "application/octet-stream"}
    try:
        async with session.get(url, headers=headers) as response:
            if response.status != http.HTTPStatus.OK:
                error_message = f"get_batched_headers_by_height failed with status: " \
                                f"{response.status}, reason: {response.reason}"
                logger.error(error_message)
                raise HeaderResponseError(error_message)
            raw_headers_array = await response.read()
            return raw_headers_array
    except aiohttp.ClientConnectionError:
        logger.error("Cannot connect to ElectrumSV-Reference Server at %s", url)
        raise ServiceUnavailableError(f"Cannot connect to ElectrumSV-Reference Server at {url}")


async def get_chain_tips_async(server_state: HeaderServerState, session: aiohttp.ClientSession) \
        -> list[Header]:
    url = f"{server_state.server_key.url}api/v1/headers/tips"
    headers = {
        "Accept": "application/octet-stream"
    }
    try:
        async with session.get(url, headers=headers) as response:
            if response.status in {http.HTTPStatus.SERVICE_UNAVAILABLE, http.HTTPStatus.NOT_FOUND}:
                raise ServiceUnavailableError("The Header API is not enabled for this server")

            if response.status != http.HTTPStatus.OK:
                error_message = f"get_chain_tips failed with status: {response.status}, " \
                                f"reason: {response.reason}"
                logger.error(error_message)
                raise HeaderResponseError(error_message)

            headers_array: bytes = await response.content.read()
            assert len(headers_array) % 84 == 0  # 80 byte header + 4 byte int32 height
            count_headers = len(headers_array) // 84
            stream = BytesIO(headers_array)

            block_headers: list[Header] = []
            for i in range(count_headers):
                raw_header = stream.read(80)
                height = bitcoinx.le_bytes_to_int(stream.read(4))
                # TODO(technical-debt) Look into why this is not `Net.COIN`?
                block_headers.append(deserialized_header(raw_header, height))
            return block_headers
    except aiohttp.ClientConnectionError:
        raise ServiceUnavailableError(f"Cannot connect to header API at {url}")


def filter_tips_for_longest_chain(tips: list[Header]) -> Header:
    longest_chain_tip = tips[0]
    for tip in tips:
        if tip.height > longest_chain_tip.height:
            longest_chain_tip = tip
    return longest_chain_tip


async def subscribe_to_headers_async(server_state: HeaderServerState,
        session: aiohttp.ClientSession) -> AsyncIterable[TipResponse]:
    url = f"{server_state.server_key.url}api/v1/headers/tips/websocket"
    try:
        async with session.ws_connect(url, timeout=5.0) as ws:
            logger.debug("Connected to %s", url)
            async for msg in ws:
                content = cast(bytes, msg.data)
                raw_header = content[0:80]
                block_hash = hash_to_hex_str(double_sha256(raw_header))
                logger.debug("Message new chain tip hash: %s", block_hash)
                height = bitcoinx.le_bytes_to_int(content[80:84])
                yield TipResponse(raw_header, height)
                if msg.type in (aiohttp.WSMsgType.CLOSED, aiohttp.WSMsgType.ERROR):
                    break
    except aiohttp.WSServerHandshakeError:
        raise ServiceUnavailableError("Websocket handshake ElectrumSV-Reference Server failed")
    except (aiohttp.ClientConnectionError, ConnectionRefusedError):
        logger.error("Cannot connect to ElectrumSV-Reference Server at %s", url)
        raise ServiceUnavailableError(f"Cannot connect to header API at {url}")


async def get_single_header_async(server_state: HeaderServerState, session: aiohttp.ClientSession,
        block_hash: bytes) -> bytes:
    url = f"{server_state.server_key.url}api/v1/headers/{hash_to_hex_str(block_hash)}"
    headers = {"Accept": "application/octet-stream"}
    try:
        async with session.get(url, headers=headers) as response:
            if response.status == http.HTTPStatus.NOT_FOUND:
                raise HeaderNotFoundError("Header with block hash "
                                            f"{hash_to_hex_str(block_hash)} not found")
            elif response.status != http.HTTPStatus.OK:
                raise HeaderResponseError("Failed to get header with status: "
                                            f"{response.status} reason: {response.reason}")
            return await response.read()
    except aiohttp.ClientConnectionError:
        logger.error("Cannot connect to ElectrumSV-Reference Server at %s", url)
        raise ServiceUnavailableError(f"Cannot connect to ElectrumSV-Reference Server at {url}")


def get_longest_valid_chain() -> Chain:
    # TODO(1.4.0) Networking UI, issue#905. This should filter out chains the user wants to ignore.
    #     It is envisaged that this will be done through the network dialog.
    assert app_state.headers is not None
    chains = list(app_state.headers.chains())
    longest_chain = chains[0]
    for chain in chains:
        if chain.chainwork > longest_chain.chainwork:
            longest_chain = chain
    return longest_chain
