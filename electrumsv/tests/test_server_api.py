from typing import cast
import unittest.mock
import uuid

import pytest

from electrumsv.constants import NetworkServerType, ServerCapability
from electrumsv.network_support import api_server, mapi
from electrumsv.types import IndefiniteCredentialId, TransactionSize


def test_get_authorization_headers_credential_none() -> None:
    config = {}
    server = api_server.NewServer("my_url", NetworkServerType.MERCHANT_API, config)
    headers = server.get_authorization_headers(None)
    assert headers == {}


default_server_header = { "Authorization": "Bearer kredential" }

server_params = [
    (None, default_server_header),
    # Just a default config, the requires entry is meaningless as it is expected to be filtered for
    # before the call to `get_authorization_headers`.
    ({ "requires_api_key": True }, default_server_header),
    # Override the api key template with a custom one.
    ({ "api_key_template": "Authorization: Bearer testnet_{API_KEY}" },
        { "Authorization": "Bearer testnet_kredential" }),
]


@pytest.mark.parametrize("params", server_params)
@unittest.mock.patch('electrumsv.network_support.api_server.app_state')
def test_get_authorization_headers_credential_default_header(app_state, params) -> None:
    config, expected_headers = params
    app_state.credentials = unittest.mock.Mock()
    app_state.credentials.get_indefinite_credential.side_effect = lambda v: "kredential"

    credential_id = cast(IndefiniteCredentialId, uuid.uuid4())
    server = api_server.NewServer("my_url", NetworkServerType.MERCHANT_API, config)
    headers = server.get_authorization_headers(credential_id)
    assert headers == expected_headers


def test_select_servers_empty_input() -> None:
    assert [] == api_server.select_servers(ServerCapability.TRANSACTION_BROADCAST, [])


def test_select_servers_filter_all_outputs() -> None:
    servers = [
        api_server.SelectionCandidate(
            NetworkServerType.MERCHANT_API,
            None,
            api_server.NewServer("A", NetworkServerType.MERCHANT_API)),
    ]
    selected_candidates = api_server.select_servers(ServerCapability.TRANSACTION_BROADCAST, servers)
    assert servers == selected_candidates


def test_select_servers_filter_reduced_outputs() -> None:
    servers = [
        api_server.SelectionCandidate(
            NetworkServerType.MERCHANT_API,
            None,
            api_server.NewServer("A", NetworkServerType.MERCHANT_API)),
    ]
    selected_candidates = api_server.select_servers(ServerCapability.FEE_QUOTE, servers)
    assert [ servers[0] ] == selected_candidates


@unittest.mock.patch('electrumsv.network_support.api_server.app_state')
def test_prioritise_broadcast_servers_invalid_candidate(app_state) -> None:
    fake_tx_size = TransactionSize(100, 20)
    dummy_server = api_server.NewServer("A", NetworkServerType.MERCHANT_API)
    dummy_server.api_key_state[None] = api_server.NewServerAccessState()
    servers = [
        api_server.SelectionCandidate(dummy_server.server_type, None, dummy_server),
    ]
    with pytest.raises(AssertionError):
        api_server.prioritise_broadcast_servers(fake_tx_size, servers)


FAKE_FEE_QUOTE_1 = {
    "fees": [
        {
            "feeType": "standard",
            "miningFee": {
                "satoshis": 500,
                "bytes": 1000,
            },
        },
    ]
}
FEE_QUOTE_1 = cast(mapi.FeeQuote, FAKE_FEE_QUOTE_1)

FAKE_FEE_QUOTE_2 = {
    "fees": [
        {
            "feeType": "standard",
            "miningFee": {
                "satoshis": 100,
                "bytes": 1000,
            },
        },
    ]
}
FEE_QUOTE_2 = cast(mapi.FeeQuote, FAKE_FEE_QUOTE_2)


@unittest.mock.patch('electrumsv.network_support.api_server.app_state')
def test_prioritise_broadcast_servers_single_candidate(app_state) -> None:
    fake_tx_size = TransactionSize(100, 20)
    dummy_server = api_server.NewServer("A", NetworkServerType.MERCHANT_API)
    key_state = dummy_server.api_key_state[None] = api_server.NewServerAccessState()
    key_state.last_fee_quote = FEE_QUOTE_1
    servers = [
        api_server.SelectionCandidate(dummy_server.server_type, None, dummy_server),
    ]
    results = api_server.prioritise_broadcast_servers(fake_tx_size, servers)
    assert len(results) == 1
    assert results[0].candidate == servers[0]
    assert results[0].initial_fee == 60


@unittest.mock.patch('electrumsv.network_support.api_server.app_state')
def test_prioritise_broadcast_servers_ordered_candidates(app_state) -> None:
    fake_tx_size = TransactionSize(100, 20)

    dummy_server1 = api_server.NewServer("A", NetworkServerType.MERCHANT_API)
    key_state1 = dummy_server1.api_key_state[None] = api_server.NewServerAccessState()
    key_state1.last_fee_quote = FEE_QUOTE_1

    dummy_server2 = api_server.NewServer("B", NetworkServerType.MERCHANT_API)
    key_state2 = dummy_server2.api_key_state[None] = api_server.NewServerAccessState()
    key_state2.last_fee_quote = FEE_QUOTE_2

    # Pass the candidates in ordered from most to least expensive.
    servers = [
        api_server.SelectionCandidate(dummy_server1.server_type, None, dummy_server1),
        api_server.SelectionCandidate(dummy_server2.server_type, None, dummy_server2),
    ]

    results = api_server.prioritise_broadcast_servers(fake_tx_size, servers)
    assert len(results) == 2

    # Verify that the prioritised candidates are ordered from least to most expensive.
    assert results[0].candidate == servers[1]
    assert results[0].initial_fee == 12

    assert results[1].candidate == servers[0]
    assert results[1].initial_fee == 60

