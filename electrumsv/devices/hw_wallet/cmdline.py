from electrumsv.logs import logs
from electrumsv.util import raw_input


class CmdLineHandler:

    def get_passphrase(self, msg, _confirm):
        import getpass
        print(msg)
        return getpass.getpass('')

    def get_pin(self, msg):
        t = { 'a':'7', 'b':'8', 'c':'9', 'd':'4', 'e':'5', 'f':'6', 'g':'1', 'h':'2', 'i':'3'}
        print(msg)
        print("a b c\nd e f\ng h i\n-----")
        o = raw_input()
        return ''.join(t[x] for x in o)

    def prompt_auth(self, msg):
        import getpass
        print(msg)
        response = getpass.getpass('')
        if len(response) == 0:
            return None
        return response

    def yes_no_question(self, msg):
        print(msg)
        return raw_input() in 'yY'

    def stop(self):
        pass

    def show_message(self, msg, on_cancel=None):
        print(msg)

    def update_status(self, b):
        logs.root.debug('trezor status %s', b)

    def finished(self):
        pass
