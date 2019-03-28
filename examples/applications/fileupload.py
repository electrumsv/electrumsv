import argparse
import base64
import datetime
import enum
import json
import hashlib
import logging
import os
import sys
import time
from typing import Tuple, Optional, List

import requests
from requests.auth import HTTPBasicAuth


def sha256(data_bytes) -> bytes:
    return hashlib.sha256(data_bytes).digest()

def sha256d(data_bytes) -> bytes:
    return sha256(sha256(data_bytes))


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

        self._session = None

    def __enter__(self) -> 'BroadcastSession':
        self._session = BroadcastSession(self)
        return self._session

    def __exit__(self, exc_type, exc_value, exc_traceback):
        try:
            self._session._save_state()
        except Exception:
            self._logger.exception("Wallet session encountered an error saving state")

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

    def make_signed_opreturn_transaction(self, pushdatas: List[bytes]) -> dict:
        pushdatas_b64 = []
        for pushdata in pushdatas:
            pushdata_b64 = base64.b64encode(pushdata).decode('utf-8')
            pushdatas_b64.append(pushdata_b64)
        params = {
            'pushdatas_b64': pushdatas_b64,
            'wallet_name': self._wallet_name,
            'password': self._wallet_password,
        }
        result = self._send_request('make_signed_opreturn_transaction', **params)
        if 'error' in result:
            return result['error']
        return result

    def broadcast_transaction(self, tx_hex: str) -> str:
        params = {
            'tx_hex': tx_hex,
        }
        result = self._send_request('broadcast_transaction', **params)
        if 'error' in result:
            return result['error']
        return result

    def check_transaction_in_wallet(self, tx_id: str) -> bool:
        params = {
            'tx_id': tx_id,
            'wallet_name': self._wallet_name,
        }
        return self._send_request('check_transaction_in_wallet', **params)

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
            raise SessionError(error_message)
        return response['result']


class SessionError(Exception):
    pass


class FileProtocol(enum.IntEnum):
    B = 1
    Bcat = 2


STATE_DIR_NAME = ".fileupload_state"

class BroadcastSession:
    def __init__(self, wallet):
        self._state = None
        self._state_path = None
        self._wallet = wallet

        self._logger = logging.getLogger("wallet-session")

    def broadcast_file(self, file_path: str, media_type: str, protocol: FileProtocol):
        with open(file_path, "rb") as f:
            message_bytes = f.read()
        file_name = os.path.basename(file_path)

        self._wallet.load_wallet()

        # These should be deterministically generated from the given file.
        initial_push_groups = self._create_initial_push_groups(
            message_bytes=message_bytes,
            media_type=media_type,
            protocol=protocol)

        self._load_state(file_name, message_bytes, initial_push_groups)

        # Broadcast and confirm in mempool for each initial transaction.
        self._process_push_groups(initial_push_groups, self._state['initial_group_state'])

        # Now that the initial transactions are confirmed to be 0-conf on-chain, create any
        # final transactions which likely need to refer to them.
        final_push_groups = self._create_final_push_groups(media_type)
        if self._state['final_group_state'] is None:
            self._state['final_group_state'] = [ {} for i in range(len(final_push_groups))]

        self._process_push_groups(final_push_groups, self._state['final_group_state'])

        return True

    def get_summary(self) -> dict:
        initial_push_groups = self._state['initial_group_state']
        final_push_groups = self._state['final_group_state']
        result = {
            'first_timestamp': initial_push_groups[0]['when_broadcast'],
            'last_timestamp': initial_push_groups[-1]['when_broadcast'],
            'fees': sum(v['tx_fee'] for v in initial_push_groups),
            'count': len(initial_push_groups),
            'size': sum(v['tx_size'] for v in initial_push_groups),
        }
        if final_push_groups is not None and len(final_push_groups):
            result['last_timestamp'] = final_push_groups[-1]['when_broadcast']
            result['fees'] += sum(v['tx_fee'] for v in final_push_groups)
            result['size'] += sum(v['tx_size'] for v in final_push_groups)
            result['count'] += len(final_push_groups)
        return result

    def _process_push_groups(self, push_groups, push_groups_state):
        for i, push_group in enumerate(push_groups):
            state = push_groups_state[i]
            if 'tx_id' not in state:
                self._logger.debug(f"Signing tx {i}")
                sign_result = self._wallet.make_signed_opreturn_transaction(push_group)

                # Record metadata that we created a signed transaction for this group.
                state['when_signed'] = datetime.datetime.now().astimezone().isoformat()
                state['tx_id'] = sign_result['tx_id']
                state['tx_fee'] = sign_result['fee']
                state['tx_size'] = len(sign_result['tx_hex']) // 2

                print(f"Broadcasting transaction {i+1}/{len(push_groups)}")
                tx_id = self._wallet.broadcast_transaction(sign_result['tx_hex'])
                if tx_id != state['tx_id']:
                    raise SessionError(
                        f"Inconsistent tx_id, got '{tx_id}' expected '{state['tx_id']}'")
                state['when_broadcast'] = datetime.datetime.now().astimezone().isoformat()

            if 'in_mempool' not in state:
                print(f"Looking for transaction {i+1}/{len(push_groups)} in mempool")
                attempts = 0
                tx_id = state['tx_id']
                while attempts < 10:
                    if self._wallet.check_transaction_in_wallet(tx_id):
                        break
                    time.sleep(2.0)
                    attempts += 1
                if attempts == 10:
                    raise SessionError(f"Failed to find transaction in mempool '{tx_id}'")

                state['in_mempool'] = True

    def _save_state(self):
        if self._state_path is not None and self._state is not None:
            with open(self._state_path, "w") as f:
                json.dump(self._state, f)

    def _load_state(self, file_name:str, message_bytes: bytes,
            initial_push_groups: List[List[bytes]]) -> None:
        message_hash = sha256(message_bytes)
        message_hash_hex = message_hash.hex()

        if not os.path.exists(STATE_DIR_NAME):
            os.mkdir(STATE_DIR_NAME)
        self._state_path = os.path.join(STATE_DIR_NAME, message_hash_hex+ ".json")

        if os.path.exists(self._state_path):
            with open(self._state_path, "r") as f:
                self._state = json.load(f)
        else:
            self._state = {}
            self._state['file_name'] = file_name
            self._state['initial_group_state'] = [ {} for i in range(len(initial_push_groups)) ]
            self._state['final_group_state'] = None

    def _create_initial_push_groups(self,
            message_bytes: bytes, media_type: str, protocol: int=FileProtocol.B,
            encoding: Optional[str]=None, file_name: Optional[str]=None) -> List[List[bytes]]:
        FileProtocol(protocol)
        assert media_type is not None

        if len(message_bytes) > 99000:
            if protocol == FileProtocol.B:
                raise SessionError("message too large for B protocol")
        else:
            if protocol == FileProtocol.Bcat:
                raise SessionError("message too small for Bcat protocol")

        all_push_groups = []

        if protocol == FileProtocol.B:
            push_values = [
                b"19HxigV4QyBv3tHpQVcUEQyq1pzZVdoAut",
                message_bytes,
                bytes(media_type, "utf-8"),
            ]
            if encoding:
                push_values.append(bytes(encoding, "utf-8"))
            if file_name:
                if not encoding:
                    raise SessionError("must provide encoding with filename")
                push_values.append(bytes(file_name, "utf-8"))
            all_push_groups.append(push_values)
        elif protocol == FileProtocol.Bcat:
            # Split the message up into OP_RETURN sized segments.
            index = 0
            message_view = memoryview(message_bytes)
            while index < len(message_view):
                segment_bytes = bytes(message_view[index:index+99000])

                push_values = [
                    b"1ChDHzdd1H4wSjgGMHyndZm6qxEDGjqpJL",
                    segment_bytes
                ]
                all_push_groups.append(push_values)
                index += 99000

        return all_push_groups

    def _create_final_push_groups(self, media_type: str,
            protocol: int=FileProtocol.B, encoding: Optional[str]=None,
            file_name: Optional[str]=None) -> List[List[bytes]]:
        FileProtocol(protocol)

        all_push_groups = []

        if protocol == FileProtocol.Bcat:
            push_values = [
                b"15DHFxWZJT58f9nhyGnsRBqrgwK4W6h4Up",
                b"ElectrumSV",
                bytes(media_type, "utf-8"),
                bytes(encoding, "utf-8") if encoding is not None else b"",
                bytes(file_name, "utf-8") if file_name is not None else b"",
                b"",
            ]
            for group_state in self._state['initial_group_state']:
                tx_id_hex = group_state['tx_id']
                tx_id_bytes = bytes.fromhex(tx_id_hex)[::-1]
                push_values.append(tx_id_bytes)

            all_push_groups.append(push_values)

        return all_push_groups


def check_file_for_protocol(filepath: str, protocol: FileProtocol) -> bool:
    if os.path.getsize(filepath) > 99000:
        return protocol != FileProtocol.B
    else:
        return protocol != FileProtocol.Bcat


def main() -> None:
    logging.basicConfig()

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
    parser.add_argument("-pr", "--protocol", action="store", default='B',
        choices = ('B', 'Bcat'), help="Specify file protocol")
    parser.add_argument("-v", "--verbose", action="store_true", default=False)
    result = parser.parse_args(sys.argv[1:])

    if result.verbose:
        print(result)
        logging.getLogger().setLevel(logging.DEBUG)

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

    # The arg parser guards against the user choosing a non-existent protocol.
    protocol = FileProtocol[result.protocol]
    if not check_file_for_protocol(filepath, protocol):
        print(f"{filepath}: incompatible with protocol (too large? too small?)")
        sys.exit(1)

    electrum_host = result.electrum_host
    if result.electrum_host is None:
        electrum_host = "127.0.0.1"

    wallet = WalletClient(electrum_host, result.electrum_port, result.rpc_username,
        result.rpc_password, result.wallet_name, result.wallet_password)
    with wallet as session:
        session.broadcast_file(filepath, media_type, protocol)

        result = session.get_summary()
        print(f"Number of transactions:      {result['count']}")
        print(f"Fees paid (per/KiB):         {result['fees']/result['size']:0.3f} satoshis")
        print(f"Fees paid (total):           {result['fees']} satoshis")
        print(f"First transaction broadcast: {result['first_timestamp']}")
        print(f"Last transaction broadcast:  {result['last_timestamp']}")


if __name__ == "__main__":
    main()

