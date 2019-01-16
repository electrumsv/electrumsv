from electrumsv.logs import logs


logger = logs.get_logger("plugin.trezor.transport")


class TrezorTransport:

    def enumerate_devices(self):
        """Just like trezorlib.transport.enumerate_devices,
        but with exception catching, so that transports can fail separately.
        """
        devices = []
        for transport in self.all_transports():
            try:
                new_devices = transport.enumerate()
            except Exception as e:
                logger.error('enumerate failed for %s. error %s', transport.__name__, e)
            else:
                devices.extend(new_devices)
        return devices

    def get_transport(self, path=None):
        """Reimplemented trezorlib.transport.get_transport,
        (1) for old trezorlib
        (2) to be able to disable specific transports
        (3) to call our own enumerate_devices that catches exceptions
        """
        if path is None:
            try:
                return self.enumerate_devices()[0]
            except IndexError:
                raise Exception("No TREZOR device found") from None

        def match_prefix(a, b):
            return a.startswith(b) or b.startswith(a)
        transports = [t for t in self.all_transports() if match_prefix(path, t.PATH_PREFIX)]
        if transports:
            return transports[0].find_by_path(path)
        raise Exception("Unknown path prefix '%s'" % path)
