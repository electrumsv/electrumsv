from electrumsv.logs import logs

class LocalRPCFunctions:
    def __init__(self) -> None:
        self._logger = logs.get_logger("local-rpc")

    def test123(self):
        return 123
