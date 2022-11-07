import electrumsv
import electrumsv.restapi
from electrumsv.restapi import get_network_type


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


def test_get_network_type(monkeypatch):
    monkeypatch.setattr(electrumsv.restapi, 'get_app_state', fake_get_app_state_main)
    assert get_network_type() == 'mainnet'
    monkeypatch.setattr(electrumsv.restapi, 'get_app_state', fake_get_app_state_test)
    assert get_network_type() == 'testnet'
    monkeypatch.setattr(electrumsv.restapi, 'get_app_state', fake_get_app_state_stn)
    assert get_network_type() == 'scalingtestnet'
