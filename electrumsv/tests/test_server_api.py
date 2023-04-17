from typing import cast
import unittest.mock
import uuid

import pytest

from electrumsv.constants import NetworkServerFlag, NetworkServerType
from electrumsv.network_support import api_server
from electrumsv.standards.mapi import FeeQuote
from electrumsv.types import IndefiniteCredentialId
from electrumsv.wallet_database.types import NetworkServerRow


def test_get_authorization_headers_credential_none() -> None:
    row = NetworkServerRow(1, NetworkServerType.MERCHANT_API, "url", 1, NetworkServerFlag.NONE,
        None, None, None, None, 0, 0, 1, 1)
    server = api_server.NewServer("my_url/", NetworkServerType.MERCHANT_API, row, None)
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
    server = api_server.NewServer("my_url/", NetworkServerType.MERCHANT_API, row, credential_id)
    mock_row = unittest.mock.Mock()
    mock_row.api_key_template = use_this_value
    server.database_rows[None] = cast(NetworkServerRow, mock_row)
    headers = server.get_authorization_headers(credential_id)
    assert headers == expected_headers



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
FEE_QUOTE_1 = cast(FeeQuote, FAKE_FEE_QUOTE_1)

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
FEE_QUOTE_2 = cast(FeeQuote, FAKE_FEE_QUOTE_2)

