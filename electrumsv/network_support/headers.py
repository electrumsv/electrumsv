import asyncio
import concurrent.futures
import dataclasses
import http
from typing import AsyncIterable, cast, Optional

import aiohttp
import bitcoinx
from bitcoinx import Chain, double_sha256, hash_to_hex_str, Header

from ..exceptions import ServiceUnavailableError
from ..logs import logs
from ..networks import Net
from ..types import ServerAccountKey

from .esv_client_types import TipResponse
from .exceptions import HeaderResponseError

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

    chain: Optional[Chain] = None
    tip_header: Optional[Header] = None
    synchronisation_data: Optional[tuple[int, int]] = None

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
        -> Header:
    url = f"{server_state.server_key.url}api/v1/headers/tips"
    headers = {
        "Accept": "application/octet-stream"
    }
    try:
        async with session.get(url, headers=headers) as response:
            if response.status in {http.HTTPStatus.SERVICE_UNAVAILABLE,
                    http.HTTPStatus.NOT_FOUND}:
                logger.error("The Header API is not enabled for this instance of "
                                "ElectrumSV-Reference-Server")
                raise ServiceUnavailableError("The Header API is not enabled for this instance "
                    "of ElectrumSV-Reference-Server")

            if response.status != http.HTTPStatus.OK:
                error_message = f"get_chain_tips failed with status: {response.status}, " \
                                f"reason: {response.reason}"
                logger.error(error_message)
                raise HeaderResponseError(error_message)

            data: bytes = await response.content.read()
            raw_header = data[0:80]
            height = bitcoinx.le_bytes_to_int(data[80:84])
            # TODO(1.4.0) Network. This is not right. Look into why is it doing `._net`?
            return Net._net.COIN.deserialized_header(raw_header, height)
    except aiohttp.ClientConnectionError:
        raise ServiceUnavailableError(f"Cannot connect to header API at {url}")


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
                logger.info("Message new chain tip hash: %s", block_hash)
                height = bitcoinx.le_bytes_to_int(content[80:84])
                yield TipResponse(raw_header, height)
                if msg.type in (aiohttp.WSMsgType.CLOSED, aiohttp.WSMsgType.ERROR):
                    break
    except aiohttp.WSServerHandshakeError:
        raise ServiceUnavailableError("Websocket handshake ElectrumSV-Reference Server failed")
    except (aiohttp.ClientConnectionError, ConnectionRefusedError):
        logger.error("Cannot connect to ElectrumSV-Reference Server at %s", url)
        raise ServiceUnavailableError(f"Cannot connect to header API at {url}")
