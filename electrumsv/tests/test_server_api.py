from typing import cast, Optional
import unittest.mock
import uuid

import pytest

from electrumsv.constants import NetworkServerFlag, NetworkServerType, ServerCapability
from electrumsv.network_support import api_server, mapi
from electrumsv.types import IndefiniteCredentialId, TransactionSize
from electrumsv.wallet_database.types import NetworkServerRow


def test_get_authorization_headers_credential_none() -> None:
    row = NetworkServerRow(1, NetworkServerType.MERCHANT_API, "url", 1, NetworkServerFlag.NONE,
        None, None, None, None, 0, 0, 1, 1)
    server = api_server.NewServer("my_url", NetworkServerType.MERCHANT_API, row, None)
    headers = server.get_authorization_headers(None)
    assert headers == {}


server_params = [
    (None, { "Authorization": "Bearer kredential" }),
    # Override the api key template with a custom one.
    ("Authorization: Bearer testnet_{API_KEY}", { "Authorization": "Bearer testnet_kredential" }),
]


@pytest.mark.parametrize("params", server_params)
@unittest.mock.patch('electrumsv.network_support.api_server.app_state')
def test_get_authorization_headers_credential_default_header(app_state, params) -> None:
    use_this_value, expected_headers = params
    app_state.credentials = unittest.mock.Mock()
    app_state.credentials.get_indefinite_credential.side_effect = lambda v: "kredential"

    credential_id = cast(IndefiniteCredentialId, uuid.uuid4())
    row = NetworkServerRow(1, NetworkServerType.MERCHANT_API, "url", 1, NetworkServerFlag.NONE,
        None, None, None, None, 0, 0, 1, 1)
    server = api_server.NewServer("my_url", NetworkServerType.MERCHANT_API, row, credential_id)
    mock_row = unittest.mock.Mock()
    mock_row.api_key_template = use_this_value
    server.database_rows[None] = cast(NetworkServerRow, mock_row)
    headers = server.get_authorization_headers(credential_id)
    assert headers == expected_headers


@unittest.mock.patch('electrumsv.network_support.api_server.app_state')
def test_prioritise_broadcast_servers_invalid_candidate(app_state) -> None:
    row1 = NetworkServerRow(1, NetworkServerType.MERCHANT_API, "url1", 1, NetworkServerFlag.NONE,
        None, None, None, None, 0, 0, 1, 1)
    fake_tx_size = TransactionSize(100, 20)
    dummy_server = api_server.NewServer("A", NetworkServerType.MERCHANT_API, row1, None)
    dummy_server.api_key_state[None] = api_server.NewServerAccessState()
    credential_id = cast(Optional[IndefiniteCredentialId], None)
    servers = [
        (dummy_server, credential_id),
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
    row1 = NetworkServerRow(1, NetworkServerType.MERCHANT_API, "url1", 1, NetworkServerFlag.NONE,
        None, None, None, None, 0, 0, 1, 1)
    fake_tx_size = TransactionSize(100, 20)
    dummy_server = api_server.NewServer("A", NetworkServerType.MERCHANT_API, row1, None)
    key_state = dummy_server.api_key_state[None] = api_server.NewServerAccessState()
    key_state.last_fee_quote = FEE_QUOTE_1
    credential_id = cast(Optional[IndefiniteCredentialId], None)
    servers = [
        (dummy_server, credential_id),
    ]
    results = api_server.prioritise_broadcast_servers(fake_tx_size, servers)
    assert len(results) == 1
    assert results[0].server == dummy_server
    assert results[0].credential_id == credential_id
    assert results[0].initial_fee == 60


@unittest.mock.patch('electrumsv.network_support.api_server.app_state')
def test_prioritise_broadcast_servers_ordered_candidates(app_state) -> None:
    row1 = NetworkServerRow(1, NetworkServerType.MERCHANT_API, "url1", 1, NetworkServerFlag.NONE,
        None, None, None, None, 0, 0, 1, 1)
    row2 = NetworkServerRow(2, NetworkServerType.MERCHANT_API, "url2", 1, NetworkServerFlag.NONE,
        None, None, None, None, 0, 0, 1, 1)
    fake_tx_size = TransactionSize(100, 20)

    dummy_server1 = api_server.NewServer("A", NetworkServerType.MERCHANT_API, row1, None)
    key_state1 = dummy_server1.api_key_state[None] = api_server.NewServerAccessState()
    key_state1.last_fee_quote = FEE_QUOTE_1

    dummy_server2 = api_server.NewServer("B", NetworkServerType.MERCHANT_API, row2, None)
    key_state2 = dummy_server2.api_key_state[None] = api_server.NewServerAccessState()
    key_state2.last_fee_quote = FEE_QUOTE_2

    null_credential_id = cast(Optional[IndefiniteCredentialId], None)

    # Pass the candidates in ordered from most to least expensive.
    servers = [
        (dummy_server1, null_credential_id),
        (dummy_server2, null_credential_id),
    ]
    results = api_server.prioritise_broadcast_servers(fake_tx_size, servers)
    assert len(results) == 2

    # Verify that the prioritised candidates are ordered from least to most expensive.
    server_1 = [ result for result in results if result.server.server_id == 1 ][0]
    assert server_1.server == dummy_server1
    assert server_1.credential_id == null_credential_id
    assert server_1.initial_fee == 60

    server_2 = [ result for result in results if result.server.server_id == 2 ][0]
    assert server_2.server == dummy_server2
    assert server_2.credential_id == null_credential_id
    assert server_2.initial_fee == 12

