# ElectrumSV - lightweight Bitcoin SV client
# Copyright (C) 2019-2020 The ElectrumSV Developers
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

'''ElectrumSV logging facilities.'''

import logging


class Logs(object):
    '''Manages various aspects of logging.'''

    def __init__(self):
        # by default this show warnings and above.  root is a public attribute.
        self.root = logging.getLogger()
        self.stream_handler = logging.StreamHandler()
        self.add_handler(self.stream_handler)

    def add_handler(self, handler):
        formatter = logging.Formatter('%(asctime)s:' + logging.BASIC_FORMAT)
        handler.setFormatter(formatter)
        self.root.addHandler(handler)

    def remove_handler(self, handler):
        self.root.removeHandler(handler)

    def add_file_output(self, path):
        self.add_handler(logging.FileHandler(path))

    def set_stream_output(self, stream):
        # > 3.6
        # self.stream_handler.setStream(stream)
        self.remove_handler(self.stream_handler)
        self.stream_handler = logging.StreamHandler(stream)
        self.add_handler(self.stream_handler)

    def get_logger(self, name):
        return logging.getLogger(name)

    def set_level(self, level):
        '''Level can be a string, such as "info", or a constant from logging module.'''
        if isinstance(level, str):
            level = level.upper()
        self.root.setLevel(level)

    def level(self):
        return self.root.level

    def is_debug_level(self):
        return self.level() == logging.DEBUG


logs = Logs()
