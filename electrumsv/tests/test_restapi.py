from aiohttp import web

import electrumsv
from electrumsv.restapi import bad_request, Fault, not_found, internal_server_error, \
    fault_to_http_response, Errors, unauthorized, forbidden, get_network_type


class MockAppStateMain():
    def __init__(self):
        self.config = {}


class MockAppStateTest():
    def __init__(self):
        self.config = {"testnet": True}


class MockAppStateSTN():
    def __init__(self):
        self.config = {"scalingtestnet": True}


class MockAppStateRegTest():
    def __init__(self):
        self.config = {"regtest": True}


def fake_get_app_state_main():
    return MockAppStateMain()

def fake_get_app_state_test():
    return MockAppStateTest()

def fake_get_app_state_stn():
    return MockAppStateSTN()

def fake_get_app_state_regtest():
    return MockAppStateRegTest()


def test_fault_to_http_response():

    fault_negative = Fault(-1, '')
    fault_zero = Fault(0, '<message>')
    fault_4xx = Fault(40000, '<message>')
    fault_404 = Fault(40400, '<not found message>')
    fault_5xx = Fault(50000, '<message>')
    fault_other = Fault(60000, '<message>')
    assert fault_to_http_response(fault_negative)._body == \
           bad_request(fault_negative.code, fault_negative.message)._body
    assert fault_to_http_response(fault_zero)._body == \
           bad_request(fault_zero.code, fault_zero.message)._body
    assert fault_to_http_response(fault_4xx)._body == \
           bad_request(fault_4xx.code, fault_4xx.message)._body
    assert fault_to_http_response(fault_404)._body == \
           not_found(fault_404.code, fault_404.message)._body
    assert fault_to_http_response(fault_5xx)._body == \
           internal_server_error(fault_5xx.code, fault_5xx.message)._body
    assert fault_to_http_response(fault_other)._body == \
           bad_request(fault_other.code, fault_other.message)._body


def test_unauthorized():
    CODE_401 = Errors.AUTH_UNSUPPORTED_TYPE_CODE
    MESSAGE_401 = Errors.AUTH_UNSUPPORTED_TYPE_MESSAGE

    response_obj = {'code': CODE_401,
                    'message': MESSAGE_401}
    assert unauthorized(CODE_401, MESSAGE_401)._body == web.json_response(data=response_obj,
                                                                          status=401)._body


def test_forbidden():
    CODE_403 = Errors.AUTH_CREDENTIALS_INVALID_CODE
    MESSAGE_403 = Errors.AUTH_CREDENTIALS_INVALID_MESSAGE

    response_obj = {'code': CODE_403, 'message': MESSAGE_403}
    assert forbidden(CODE_403, MESSAGE_403)._body == web.json_response(data=response_obj,
                                                                       status=403)._body


def test_get_network_type(monkeypatch):
    monkeypatch.setattr(electrumsv.restapi, 'get_app_state', fake_get_app_state_main)
    assert get_network_type() == 'main'
    monkeypatch.setattr(electrumsv.restapi, 'get_app_state', fake_get_app_state_test)
    assert get_network_type() == 'test'
    monkeypatch.setattr(electrumsv.restapi, 'get_app_state', fake_get_app_state_stn)
    assert get_network_type() == 'stn'
