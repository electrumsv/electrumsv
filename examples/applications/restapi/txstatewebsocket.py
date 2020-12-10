# Adapted from https://stackoverflow.com/questions/48695294/how-can-i-detect-the-closure-of-an-python-aiohttp-web-socket-on-the-server-when
# while looking at ways to handle the issue of when the client exits uncleanly
import json
import uuid
import weakref

import aiohttp
from aiohttp import web
from bitcoinx import hex_str_to_hash

from electrumsv.logs import logs
from electrumsv.restapi import Fault
from electrumsv.wallet import AbstractAccount

from examples.applications.restapi.handler_utils import VNAME
from examples.applications.restapi.errors import Errors


class WSClient(object):

    def __init__(self, ws_id: str, websocket: web.WebSocketResponse, account: AbstractAccount):
        # If 'account' is garbage collected prior to fully stopping the ElectrumSV application (
        # and RESTAPI), will need to force close websocket connections associated with that wallet.
        # There is currently no RESTAPI endpoint that allows stopping a wallet but would need to
        # be responsible for this cleanup process (otherwise would get a ReferenceError when
        # fetching transactions)
        self.ws_id = ws_id
        self.websocket = websocket
        self.account = weakref.proxy(account)


class TxStateWebSocket(web.View):
    """
    1) initial registration of a txid begets an initial response of current tx state
    2) app.py:RESTAPIApplication._tx_state_push_notification gives push notifications for
    subsequent state changes
    """
    logger = logs.get_logger("tx-state-websocket")

    async def get(self):
        ws = web.WebSocketResponse()
        await ws.prepare(self.request)
        ws_id = str(uuid.uuid4())

        try:
            self.restapi = self.request.app['restapi']
            self.argparser = self.restapi.argparser
            required_vars = [VNAME.WALLET_NAME, VNAME.ACCOUNT_ID]

            # argparser() raises Fault(Errors.JSON_DECODE_ERROR_CODE, msg) and
            # Fault(GENERIC_BAD_REQUEST_CODE, msg)
            vars = await self.argparser(self.request, required_vars=required_vars)
            wallet_name = vars[VNAME.WALLET_NAME]
            index = vars[VNAME.ACCOUNT_ID]

            # _load_wallet(wallet_name) raises Fault(Errors.BAD_WALLET_NAME_CODE, msg) and
            # Fault(Errors.WALLET_NOT_FOUND_CODE, msg)
            await self.restapi._load_wallet(wallet_name)

            # _get_account(wallet_name, index) raises Fault(Errors.WALLET_NOT_FOUND_CODE, msg) and
            # Fault(Errors.LOAD_BEFORE_GET_CODE, msg)
            self.account = self.restapi._get_account(wallet_name, index)

            client = WSClient(ws_id=ws_id, websocket=ws, account=self.account)
            self.request.app['ws_clients'][client.ws_id] = client
            self.logger.debug('%s connected. host=%s.', client.ws_id, self.request.host)
            await self._handle_new_txid_registration(client)
            return ws
        except Fault as e:
            await ws.send_str(json.dumps({'code': e.code, 'message': e.message}))
        finally:
            await ws.close()
            self.logger.debug("deleting %s registration", ws_id)
            del self.request.app['tx_registrations_map'][ws_id]
            del self.request.app['ws_clients'][ws_id]

    async def _handle_new_txid_registration(self, client):
        """
        for each new txid received from client -> return current status immediately
        NOTE: a separate background task pushes any new updates to the "registered" txids
        """
        self.ws_clients = self.request.app['ws_clients']
        self.tx_registrations_map = self.request.app['tx_registrations_map']

        async for msg in client.websocket:
            if msg.type == aiohttp.WSMsgType.text:
                self.logger.debug('%s client sent: %s', client.ws_id, msg.data)
                request_json = json.loads(msg.data)
                txids = request_json.get("txids")
                if not txids:
                    message = "no txids field provided in json request"
                    await client.websocket.send_str(json.dumps({
                        'code': Errors.GENERIC_BAD_REQUEST_CODE,
                        'message': message
                    }))
                    continue

                for txid in txids:
                    # 1) register new txid
                    tx_hash = hex_str_to_hash(txid)
                    if not self.tx_registrations_map.get(client.ws_id):
                        self.tx_registrations_map[client.ws_id] = set()
                    self.tx_registrations_map[client.ws_id].add(tx_hash)

                    # 2) give back initial current state of txid
                    tx_hash = hex_str_to_hash(txid)

                    # todo - this will raise ReferenceError if wallet has been stopped
                    tx_entry = client.account.get_transaction_entry(tx_hash)
                    if tx_entry:
                        response_json = json.dumps({
                            "txid": txid,
                            "tx_flags": int(tx_entry.flags)
                        })
                        self.logger.debug('%s response: %s', client.ws_id, response_json)
                        await client.websocket.send_str(response_json)
                    else:
                        message = f"txid not found: {txid}"
                        response_json = json.dumps({
                            'code': Errors.TRANSACTION_NOT_FOUND_CODE,
                            'message': message
                        })
                        self.logger.debug('%s response: %s', client.ws_id, response_json)
                        await client.websocket.send_str(response_json)

            elif msg.type == aiohttp.WSMsgType.error:
                # 'client.websocket.exception()' merely returns ClientWebSocketResponse._exception
                # without a traceback. see aiohttp.ws_client.py:receive for details.
                self.logger.error('ws connection closed with exception %s',
                    client.websocket.exception())
