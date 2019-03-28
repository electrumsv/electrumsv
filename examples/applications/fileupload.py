import argparse
import base64
import json
import logging
import os
import sys
from typing import Tuple

import requests
from requests.auth import HTTPBasicAuth


# Window 1:
# set PYTHONPATH=examples\applications
# py -3 electrum-sv -dapp fileupload

# Window 2:
# py -3 electrum-sv setconfig rpcport 8888
# py -3 electrum-sv setconfig rpcuser leo-sayer
# py -3 electrum-sv setconfig rpcpassword i-feel-like-dancing
# py -3 examples\applications\fileupload.py -f picture.jpg -u leo-sayer -p i-feel-like-dancing
#         -wn my_wallet_name -wp my_wallet_password


class WalletClient:
    _next_request_id = 0

    def __init__(self, electrum_host, electrum_port, rpc_username, rpc_password, wallet_name,
                 wallet_password=None):
        self._logger = logging.getLogger("wallet-client")

        self._electrum_host = electrum_host
        self._electrum_port = electrum_port
        self._rpc_username = rpc_username
        self._rpc_password = rpc_password
        self._wallet_name = wallet_name
        self._wallet_password = wallet_password

    def load_wallet(self) -> None:
        params = {
            'wallet_name': self._wallet_name,
        }
        if self._wallet_password is not None:
            params['password'] = self._wallet_password
        return self._send_request("load_wallet", **params)

    def get_balance(self) -> Tuple[int, int]:
        params = {
            'wallet_name': self._wallet_name,
        }
        if self._wallet_password is not None:
            params['password'] = self._wallet_password
        result = self._send_request("get_balance", **params)
        confirmed, unconfirmed, _unmatured = result
        return unconfirmed, confirmed

    def create_file_transactions(self, file_bytes: bytes, media_type: str) -> Tuple[str, str]:
        protocol = 1
        if len(file_bytes) > 99000:
            protocol = 2
        b64message = base64.b64encode(file_bytes).decode('utf-8')
        params = {
            'b64message': b64message,
            'media_type': media_type,
            'wallet_name': self._wallet_name,
            'password': self._wallet_password,
            'protocol': protocol,
        }
        result = self._send_request('create_file_transactions', **params)
        if 'error' in result:
            return result['error']
        return result

    def broadcast_transaction(self, tx_hex: str):
        params = {
            'tx_hex': tx_hex,
        }
        result = self._send_request('broadcast_transaction', **params)
        if 'error' in result:
            return result['error']
        return result

    def _send_request(self, method, *args, **kwargs):
        # JSON-RPC 2.0 allows either a list of arguments or a dictionary of named arguments,
        # but not both.
        assert not (len(args) and len(kwargs))
        params = args
        if not len(params) and len(kwargs):
            params = kwargs

        url = f"http://{self._electrum_host}:{self._electrum_port}/"
        headers = {'content-type': 'application/json'}

        request_id = self._next_request_id
        self._next_request_id += 1
        payload = {
            "method": method,
            "params": params,
            "jsonrpc": "2.0",
            "id": request_id,
        }
        response = requests.post(url, data=json.dumps(payload), headers=headers,
            auth=HTTPBasicAuth(self._rpc_username, self._rpc_username)).json()
        self._logger.debug("_send_request(%s, *%s, **%s) -> %s", method, args, kwargs, response)
        if 'error' in response:
            error_message = response['error'].get('message', 'Server did not give reason')
            raise Exception(error_message)
        return response['result']



def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--file", required=True)
    parser.add_argument("-mt", "--media-type", required=False)
    parser.add_argument("-enc", "--encoding", required=False)
    parser.add_argument("-fn", "--filename", required=False)
    parser.add_argument("-eh", "--electrum-host", required=False)
    parser.add_argument("-ep", "--electrum-port", required=False, default=8888, type=int)
    parser.add_argument("-u", "--rpc-username", required=True)
    parser.add_argument("-p", "--rpc-password", required=True)
    parser.add_argument("-wn", "--wallet-name", required=True)
    parser.add_argument("-wp", "--wallet-password", required=True)
    result = parser.parse_args(sys.argv[1:])
    print(result)

    filepath = result.file
    if not os.path.exists(filepath):
        print(f"{filepath}: file not found")
        sys.exit(1)

    suffix = os.path.splitext(filepath)[1].lower()
    media_type = result.media_type
    if media_type is None and suffix:
        if suffix == ".png":
            media_type = "image/png"
        elif suffix == ".jpeg" or suffix == ".jpg":
            media_type = "image/jpeg"
        elif suffix == ".mp4":
            media_type = "video/mp4"

        if media_type is None:
            print(f"{filepath}: unable to guess media type")
            sys.exit(1)

    electrum_host = result.electrum_host
    if result.electrum_host is None:
        electrum_host = "127.0.0.1"

    wallet = WalletClient(result.electrum_host, result.electrum_port, result.rpc_username,
        result.rpc_password, result.wallet_name, result.wallet_password)

    # This will load the wallet if it succeeds, or exit displaying the error.
    try:
        wallet.load_wallet()
    except Exception as e:
        # Perhaps ElectrumSV is not running.  Or wrong port. Or wrong password.
        print(str(e))
        sys.exit(1)

    with open(filepath, "rb") as f:
        data = f.read()
        broadcast_result = wallet.create_file_transactions(data, media_type)

    write_file_index = 0
    while True:
        write_file_name = "broadcast_state_%04d.json" % write_file_index
        if not os.path.exists(write_file_name):
            break
        write_file_index += 1

    print(f"Writing transaction data to '{write_file_name}'")
    with open(write_file_name, "w") as f:
        json.dump(broadcast_result, f)

    for this_result in broadcast_result:
        print(f"Broadcasting tx '{this_result['tx_id']}' with fee {this_result['fee']}")
        wallet.broadcast_transaction(this_result['tx_hex'])



if __name__ == "__main__":
    main()

