# Pytest looks here for fixtures

import pytest
from electrumsv.networks import Net, SVMainnet, SVTestnet


@pytest.fixture(params=(SVMainnet, SVTestnet))
def coin(request):
    network = request.param
    Net.set_to(network)
    try:
        yield network.COIN
    finally:
        Net.set_to(SVMainnet)
