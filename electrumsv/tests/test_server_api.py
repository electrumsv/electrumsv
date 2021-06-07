from typing import cast
import unittest.mock
import uuid

import pytest

from electrumsv.constants import NetworkServerType
from electrumsv.network_support import api_server
from electrumsv.types import IndefiniteCredentialId


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
