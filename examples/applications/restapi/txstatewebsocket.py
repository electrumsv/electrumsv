# Adapted from https://stackoverflow.com/questions/48695294/how-can-i-detect-the-closure-of-an-python-aiohttp-web-socket-on-the-server-when
# while looking at ways to handle the issue of when the client exits uncleanly
import json
import uuid
import asyncio
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
        self.ws_id = ws_id
        self.websocket = websocket
        self.account = account


class TxStateWebSocket(web.View):
    """
    Todo: test that Basic Auth covers this endpoint too
    1) initial registration of a txid begets an initial response of current tx state
    2) app.py:RESTAPIApplication._tx_state_push_notification gives push notifications for
    subsequent state changes
    """
    logger = logs.get_logger("tx-state-websocket")

    async def get(self):
        ws = web.WebSocketResponse()
        await ws.prepare(self.request)

        try:
            self.restapi = self.request.app['restapi']
            self.argparser = self.restapi.argparser
            required_vars = [VNAME.WALLET_NAME, VNAME.ACCOUNT_ID]
            vars = await self.argparser(self.request, required_vars=required_vars)
            wallet_name = vars[VNAME.WALLET_NAME]
            index = vars[VNAME.ACCOUNT_ID]

            await self.restapi._load_wallet(wallet_name)
            self.account = self.restapi._get_account(wallet_name, index)

            ws_id = str(uuid.uuid4())
            client = WSClient(ws_id=ws_id, websocket=ws, account=self.account)
            self.request.app['ws_clients'][client.ws_id] = client
            self.logger.debug('%s connected. host=%s.' % (client.ws_id, self.request.host))
            try:
                await self._handle_new_txid_registration(client)
            finally:
                await ws.close()
                del self.request.app['ws_clients'][client.ws_id]
                self.logger.debug('%s disconnected' % client.ws_id)
            return ws
        except Fault as e:
            await ws.send_str(json.dumps({'code': e.code, 'message': e.message}))
        finally:
            await ws.close()

    async def _handle_new_txid_registration(self, client):
        """
        for each new txid received from client -> return current status immediately
        NOTE: a separate background task pushes any new updates to the "registered" txids
        """
        self.ws_clients = self.request.app['ws_clients']
        self.tx_registrations_map = self.request.app['tx_registrations_map']

        async for msg in client.websocket:
            if msg.type == aiohttp.WSMsgType.text:
                if msg.data == 'close':
                    await client.websocket.close()
                else:
                    self.logger.debug('%s sent: %s' % (client.ws_id, msg.data))
                    try:
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
                            if not self.tx_registrations_map.get(tx_hash):
                                self.tx_registrations_map[tx_hash] = set()
                            self.tx_registrations_map[tx_hash].add(client.ws_id)

                            # 2) give back initial current state of txid
                            tx_hash = hex_str_to_hash(txid)
                            tx_entry = client.account.get_transaction_entry(tx_hash)
                            if tx_entry:
                                response_json = json.dumps({
                                    "txid": txid,
                                    "tx_flags": int(tx_entry.flags)
                                })
                                await client.websocket.send_str(response_json)
                            else:
                                message = f"txid not found :{txid}"
                                await client.websocket.send_str(json.dumps({
                                    'code': Errors.TRANSACTION_NOT_FOUND_CODE,
                                    'message': message
                                }))
                                continue
                        await asyncio.sleep(0)
                    except:
                        self.logger.error(client.websocket.exception())

            elif msg.type == aiohttp.WSMsgType.error:
                self.logger.error('ws connection closed with exception %s' %
                              client.websocket.exception())
