# Open BSV License version 4
#
# Copyright (c) 2021 Bitcoin Association for BSV ("Bitcoin Association")
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# 1 - The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# 2 - The Software, and any software that is derived from the Software or parts thereof,
# can only be used on the Bitcoin SV blockchains. The Bitcoin SV blockchains are defined,
# for purposes of this license, as the Bitcoin blockchain containing block height #556767
# with the hash "000000000000000001d956714215d96ffc00e0afda4cd0a96c96f8d802b1662b" and
# that contains the longest persistent chain of blocks accepted by this Software and which
# are valid under the rules set forth in the Bitcoin white paper (S. Nakamoto, Bitcoin: A
# Peer-to-Peer Electronic Cash System, posted online October 2008) and the latest version
# of this Software available in this repository or another repository designated by Bitcoin
# Association, as well as the test blockchains that contain the longest persistent chains
# of blocks accepted by this Software and which are valid under the rules set forth in the
# Bitcoin whitepaper (S. Nakamoto, Bitcoin: A Peer-to-Peer Electronic Cash System, posted
# online October 2008) and the latest version of this Software available in this repository,
# or another repository designated by Bitcoin Association
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

import enum
import json
from typing import AsyncIterable, List, NamedTuple, Optional, TypedDict

import aiohttp
import struct


class MatchFlags(enum.IntFlag):
    # The match is in a transaction output.
    IN_OUTPUT = 1 << 0
    # The match is in a transaction input.
    IN_INPUT = 1 << 1


class RestorationFilterRequest(TypedDict):
    filterKeys: List[str]

class RestorationFilterJSONResponse(TypedDict):
    pushDataHashHex: str
    transactionId: str
    index: int
    referenceType: int
    spendTransactionId: Optional[str]
    spendInputIndex: int

class RestorationFilterResult(NamedTuple):
    flags: MatchFlags
    push_data_hash: bytes
    transaction_hash: bytes
    # EMPTY_HASH is present in the case of no known spend transaction.
    spend_transaction_hash: bytes
    transaction_output_index: int
    # 0xFFFFFFFF is present in the case of no known spend transaction.
    spend_input_index: int


RESULT_UNPACK_FORMAT = ">c32s32s32sii"
FILTER_RESPONSE_SIZE = 1 + 32 + 32 + 32 + 4 + 4
assert struct.calcsize(RESULT_UNPACK_FORMAT) == FILTER_RESPONSE_SIZE


class GeneralAPIError(Exception):
    pass

class FilterResponseInvalidError(GeneralAPIError):
    pass

class FilterResponseIncompleteError(GeneralAPIError):
    pass


async def post_restoration_filter_request_json(url: str, request_data: RestorationFilterRequest) \
        -> AsyncIterable[RestorationFilterJSONResponse]:
    """
    This will stream matches for the given push data hashes from the server in JSON
    structures until there are no more matches.

    Raises `HTTPError` if the response status code indicates an error occurred.
    Raises `FilterResponseInvalidError` if the response content type does not match what we accept.
    """
    headers={
        'Content-Type':     'application/json',
        'Accept':           'application/json',
        'User-Agent':       'ElectrumSV'
    }
    async with aiohttp.ClientSession(headers=headers) as session:
        async with session.post(url, json=request_data) as response:
            content_type, *content_type_extra = response.headers["Content-Type"].split(";")
            if content_type != "application/octet-stream":
                raise FilterResponseInvalidError(
                    "Invalid response content type, got {}, expected {}".format(content_type,
                        "octet-stream"))
            async for response_line in response.content:
                yield json.loads(response_line)


async def post_restoration_filter_request_binary(url: str, request_data: RestorationFilterRequest) \
        -> AsyncIterable[bytes]:
    """
    This will stream matches for the given push data hashes from the server in packed binary
    structures until there are no more matches.

    Raises `FilterResponseInvalidError` if the response content type does not match what we accept.
    Raises `FilterResponseIncompleteError` if a response packet is incomplete. This likely means
      that the connection was closed mid-transmission.
    Raises `aiohttp.client_exceptions.ClientConnectorError` if the remote computer does not accept
      the connection.
    """
    headers={
        'Content-Type':     'application/json',
        'Accept':           'application/octet-stream',
        'User-Agent':       'ElectrumSV'
    }
    async with aiohttp.ClientSession(headers=headers) as session:
        async with session.post(url, json=request_data) as response:
            content_type, *content_type_extra = response.headers["Content-Type"].split(";")
            if content_type != "application/octet-stream":
                raise FilterResponseInvalidError(
                    "Invalid response content type, got {}, expected {}".format(content_type,
                        "octet-stream"))
            packet_bytes: bytes
            async for packet_bytes in response.content.iter_chunked(FILTER_RESPONSE_SIZE):
                if len(packet_bytes) != FILTER_RESPONSE_SIZE:
                    if len(packet_bytes) == 1 and packet_bytes == b"\0":
                        # Sending a null byte indicates a successful end of matches.
                        break
                    raise FilterResponseIncompleteError("Only received ")
                yield packet_bytes


def unpack_binary_restoration_entry(entry_data: bytes) -> RestorationFilterResult:
    assert len(entry_data) == FILTER_RESPONSE_SIZE
    return RestorationFilterResult(*struct.unpack(RESULT_UNPACK_FORMAT, entry_data))

