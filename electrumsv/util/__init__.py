# ElectrumSV - lightweight Bitcoin SV client
# Copyright (C) 2019-2020 The ElectrumSV Developers
# Copyright (C) 2011 Thomas Voegtlin
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

from collections import defaultdict
from decimal import Decimal
from datetime import datetime
import json
import hmac
import os
import socket
import ssl
import stat
import sys
import threading
import time
import types
from typing import Any, cast, Dict, Iterable, List, Optional, Sequence, Tuple

from bitcoinx import PublicKey, be_bytes_to_int

from ..logs import logs
from ..startup import package_dir
from ..version import PACKAGE_DATE


def inv_dict(d):
    return {v: k for k, v in d.items()}


def protocol_tuple(s):
    '''Converts a protocol version number, such as "1.0" to a tuple (1, 0).

    If the version number is bad, (0, ) indicating version 0 is returned.'''
    try:
        return tuple(int(part) for part in s.split('.'))
    except (TypeError, ValueError, AttributeError):
        raise ValueError(f'invalid protocol version: {s}') from None


def version_string(ptuple):
    '''Convert a version tuple such as (1, 2) to "1.2".
    There is always at least one dot, so (1, ) becomes "1.0".'''
    while len(ptuple) < 2:
        ptuple += (0, )
    return '.'.join(str(p) for p in ptuple)


class MyEncoder(json.JSONEncoder):
    # https://github.com/PyCQA/pylint/issues/414
    def default(self, o): # pylint: disable=method-hidden
        from ..transaction import Transaction
        if isinstance(o, Transaction):
            return o.to_dict()
        return super(MyEncoder, self).default(o)


class JSON:

    classes: Dict[Any, Any] = {}

    @classmethod
    def register(cls, *classes):
        for klass in classes:
            cls.classes[klass.__name__] = klass

    @classmethod
    def dumps(cls, obj, **kwargs):
        def encode_obj(obj):
            class_name = obj.__class__.__name__
            if class_name not in cls.classes:
                raise TypeError(f'object of type {class_name} is not JSON serializable')
            return {'_sv': (class_name, obj.to_json())}

        kwargs['default'] = encode_obj
        return json.dumps(obj, **kwargs)

    @classmethod
    def loads(cls, s, **kwargs):
        def decode_obj(obj):
            if '_sv' in obj:
                class_name, ser = obj['_sv']
                obj = cls.classes[class_name].from_json(ser)
            return obj

        kwargs['object_hook'] = decode_obj
        return json.loads(s, **kwargs)


class DaemonThread(threading.Thread):
    """ daemon thread that terminates cleanly """

    def __init__(self, name):
        threading.Thread.__init__(self)
        self.name = name
        self.parent_thread = threading.currentThread()
        self.running = False
        self.running_lock = threading.Lock()
        self.job_lock = threading.Lock()
        self.jobs = []
        self.logger = logs.get_logger(f'{name} thread')

    def add_jobs(self, jobs):
        with self.job_lock:
            self.jobs.extend(jobs)

    def run_jobs(self):
        # Don't let a throwing job disrupt the thread, future runs of
        # itself, or other jobs.  This is useful protection against
        # malformed or malicious server responses
        with self.job_lock:
            for job in self.jobs:
                try:
                    job.run()
                except Exception as e:
                    self.logger.exception("running job")

    def remove_jobs(self, jobs):
        with self.job_lock:
            for job in jobs:
                self.jobs.remove(job)

    def start(self):
        with self.running_lock:
            self.running = True
        return threading.Thread.start(self)

    def is_running(self):
        with self.running_lock:
            return self.running and self.parent_thread.is_alive()

    def stop(self):
        with self.running_lock:
            self.running = False

    def on_stop(self):
        self.logger.debug("stopped")


# Method decorator.  To be used for calculations that will always
# deliver the same result.  The method cannot take any arguments
# and should be accessed as an attribute.
class cachedproperty(object):

    def __init__(self, f):
        self.f = f

    def __get__(self, obj, type):
        obj = obj or type
        value = self.f(obj)
        setattr(obj, self.f.__name__, value)
        return value

def json_encode(obj):
    try:
        s = json.dumps(obj, sort_keys = True, indent = 4, cls=MyEncoder)
    except TypeError:
        s = repr(obj)
    return s

def json_decode(x):
    try:
        return json.loads(x, parse_float=Decimal)
    except Exception:
        return x


# taken from Django Source Code
def constant_time_compare(val1, val2):
    """Return True if the two strings are equal, False otherwise."""
    return hmac.compare_digest(to_bytes(val1, 'utf8'), to_bytes(val2, 'utf8'))


# decorator that prints execution time
def profiler(func):
    def do_profile(func, args, kw_args):
        n = func.__name__
        logger = logs.get_logger("profiler")
        t0 = time.time()
        o = func(*args, **kw_args)
        t = time.time() - t0
        logger.debug("%s %.4f", n, t)
        return o
    return lambda *args, **kw_args: do_profile(func, args, kw_args)


def android_ext_dir():
    try:
        import jnius
        env = jnius.autoclass('android.os.Environment')
    except ImportError:
        from android.os import Environment as env  # Chaquopy import hook
    return env.getExternalStorageDirectory().getPath()


def assert_datadir_available(config_path):
    path = config_path
    if os.path.exists(path):
        return
    else:
        raise FileNotFoundError(
            'ElectrumSV datadir does not exist. Was it deleted while running?' + '\n' +
            'Should be at {}'.format(path))

def assert_file_in_datadir_available(path, config_path):
    if os.path.exists(path):
        return
    else:
        assert_datadir_available(config_path)
        raise FileNotFoundError(
            'Cannot find file but datadir is there.' + '\n' +
            'Should be at {}'.format(path))

def assert_bytes(*args):
    """
    porting helper, assert args type
    """
    try:
        for x in args:
            assert isinstance(x, (bytes, bytearray))
    except AssertionError:
        logs.root.error('assert bytes failed %s', [type(arg) for arg in args])
        raise


def assert_str(*args):
    """
    porting helper, assert args type
    """
    for x in args:
        assert isinstance(x, str)


def random_integer(nbits):
    nbytes = (nbits + 7) // 8
    return be_bytes_to_int(os.urandom(nbytes)) % (1 << nbits)


def to_string(x, enc):
    if isinstance(x, (bytes, bytearray)):
        return x.decode(enc)
    if isinstance(x, str):
        return x
    else:
        raise TypeError("Not a string or bytes like object")

def to_bytes(something, encoding='utf8') -> bytes:
    """
    cast string to bytes() like object, but for python2 support it's bytearray copy
    """
    if isinstance(something, bytes):
        return something
    if isinstance(something, str):
        return something.encode(encoding)
    elif isinstance(something, bytearray):
        return bytes(something)
    else:
        raise TypeError("Not a string or bytes like object")


bfh = bytes.fromhex


def bh2u(x):
    """
    str with hex representation of a bytes-like object

    >>> x = bytes((1, 2, 10))
    >>> bh2u(x)
    '01020A'

    :param x: bytes
    :rtype: str
    """
    return x.hex()

def get_electron_cash_user_dir(esv_user_dir):
    """Convert the ESV user directory to what it would be in Electron Cash.
    This should allow the Electron Cash directory for the platform to be
    located.

    Arguments:
    esv_user_dir --- the ElectrumSV `user_dir` generated path.
    """
    from electrumsv.app_state import app_state
    if app_state.config.cmdline_options['portable']:
        esv_user_dir = esv_user_dir.replace("electrum_sv_data", "electron_cash_data")
    else:
        esv_user_dir = esv_user_dir.replace(".electrum-sv", ".electron-cash")
        esv_user_dir = esv_user_dir.replace("ElectrumSV", "ElectronCash")
    return esv_user_dir


def make_dir(path):
    # Make directory if it does not yet exist.
    if not os.path.exists(path):
        if os.path.islink(path):
            raise Exception('Dangling link: ' + path)
        os.mkdir(path)
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)


def format_satoshis_plain(x, decimal_point = 8):
    """Display a satoshi amount scaled.  Always uses a '.' as a decimal
    point and has no thousands separator"""
    scale_factor = pow(10, decimal_point)
    return "{:.8f}".format(Decimal(x) / scale_factor).rstrip('0').rstrip('.')


def format_satoshis(x: Optional[int], num_zeros=0, decimal_point=8, precision=None,
                    is_diff=False, whitespaces=False) -> str:
    from locale import localeconv
    if x is None:
        return 'unknown'
    if precision is None:
        precision = decimal_point
    decimal_format = ",.0" + str(precision) if precision > 0 else ""
    if is_diff:
        decimal_format = '+' + decimal_format
    fmt_string = "{:" + decimal_format + "f}"
    result = (fmt_string).format(x / pow (10, decimal_point)).rstrip('0')
    integer_part, fract_part = result.split(".")
    dp = cast(str, localeconv()['decimal_point'])
    if len(fract_part) < num_zeros:
        fract_part += "0" * (num_zeros - len(fract_part))
    result = integer_part + dp + fract_part
    if whitespaces:
        result += " " * (decimal_point - len(fract_part))
        result = " " * (15 - len(result)) + result
    return result

def format_fee_satoshis(fee, num_zeros=0):
    return format_satoshis(fee, num_zeros, 0, precision=num_zeros)

def timestamp_to_datetime(timestamp):
    try:
        return datetime.fromtimestamp(timestamp)
    except Exception:
        return None

def format_time(timestamp, default_text):
    date = timestamp_to_datetime(timestamp)
    return date.isoformat(' ')[:-3] if date else default_text


# Takes a timestamp and returns a string with the approximation of the age
def age(from_date, since_date = None, target_tz=None, include_seconds=False):
    if from_date is None:
        return "Unknown"

    from_date = datetime.fromtimestamp(from_date)
    if since_date is None:
        since_date = datetime.now(target_tz)

    td = time_difference(from_date - since_date, include_seconds)
    return td + " ago" if from_date < since_date else "in " + td


def time_difference(distance_in_time, include_seconds):
    #distance_in_time = since_date - from_date
    distance_in_seconds = int(round(abs(distance_in_time.days * 86400 + distance_in_time.seconds)))
    distance_in_minutes = int(round(distance_in_seconds/60))

    if distance_in_minutes <= 1:
        if include_seconds:
            for remainder in [5, 10, 20]:
                if distance_in_seconds < remainder:
                    return "less than %s seconds" % remainder
            if distance_in_seconds < 40:
                return "half a minute"
            elif distance_in_seconds < 60:
                return "less than a minute"
            else:
                return "1 minute"
        else:
            if distance_in_minutes == 0:
                return "less than a minute"
            else:
                return "1 minute"
    elif distance_in_minutes < 45:
        return "%s minutes" % distance_in_minutes
    elif distance_in_minutes < 90:
        return "about 1 hour"
    elif distance_in_minutes < 1440:
        return "about %d hours" % (round(distance_in_minutes / 60.0))
    elif distance_in_minutes < 2880:
        return "1 day"
    elif distance_in_minutes < 43220:
        return "%d days" % (round(distance_in_minutes / 1440))
    elif distance_in_minutes < 86400:
        return "about 1 month"
    elif distance_in_minutes < 525600:
        return "%d months" % (round(distance_in_minutes / 43200))
    elif distance_in_minutes < 1051200:
        return "about 1 year"
    else:
        return "over %d years" % (round(distance_in_minutes / 525600))

# Python bug (http://bugs.python.org/issue1927) causes raw_input
# to be redirected improperly between stdin/stderr on Unix systems
#TODO: py3
def raw_input(prompt=None):
    if prompt:
        sys.stdout.write(prompt)
    return builtin_raw_input()

import builtins
builtin_raw_input = builtins.input
builtins.input = raw_input


def parse_json(message):
    # TODO: check \r\n pattern
    n = message.find(b'\n')
    if n==-1:
        return None, message
    try:
        j = json.loads(message[0:n].decode('utf8'))
    except Exception:
        j = None
    return j, message[n+1:]


class timeout(Exception):
    pass

TimeoutException = timeout # Future compat. with Electrum codebase/cherrypicking


class SocketPipe:
    def __init__(self, socket):
        self.socket = socket
        self.message = b''
        self.set_timeout(0.1)
        self.recv_time = time.time()
        self.logger = logs.get_logger('SocketPipe')

    def set_timeout(self, t):
        self.socket.settimeout(t)

    def idle_time(self):
        return time.time() - self.recv_time

    def get(self):
        while True:
            response, self.message = parse_json(self.message)
            if response is not None:
                return response
            try:
                data = self.socket.recv(1024)
            except socket.timeout:
                raise timeout
            except ssl.SSLError:
                raise timeout
            except socket.error as err:
                if err.errno == 60:
                    raise timeout
                elif err.errno in [11, 35, 10035]:
                    self.logger.info("socket errno %d (resource temporarily unavailable)",
                                     err.errno)
                    time.sleep(0.2)
                    raise timeout
                else:
                    self.logger.exception(f"socket.recv unknown socket.error {err.errno}")
                    data = b''
            except Exception as e:
                self.logger.exception("socket.recv unknown exception {e}")
                data = b''

            if not data:  # Connection closed remotely
                return None
            self.message += data
            self.recv_time = time.time()

    def send(self, request):
        out = json.dumps(request) + '\n'
        out = out.encode('utf8')
        self._send(out)

    def send_all(self, requests):
        out = b''.join((json.dumps(request) + '\n').encode('utf8') for request in requests)
        self._send(out)

    def _send(self, out):
        while out:
            sent = self.socket.send(out)
            out = out[sent:]


def setup_thread_excepthook():
    """
    Workaround for `sys.excepthook` thread bug from:
    http://bugs.python.org/issue1230540

    Call once from the main thread before creating any threads.
    """

    init_original = threading.Thread.__init__

    def init(self, *args, **kwargs):

        init_original(self, *args, **kwargs)
        run_original = self.run

        def run_with_except_hook(*args2, **kwargs2):
            try:
                run_original(*args2, **kwargs2)
            except Exception:
                sys.excepthook(*sys.exc_info())

        self.run = run_with_except_hook

    threading.Thread.__init__ = init


def get_wallet_name_from_path(wallet_path: str) -> str:
    return os.path.splitext(os.path.basename(wallet_path))[0]

def versiontuple(v: str) -> Sequence[int]:
    return tuple(int(x) for x in v.split("."))

def resource_path(*parts: Sequence[str]) -> str:
    return os.path.join(package_dir, "data", *parts) # type: ignore

def read_resource_file(filename: str) -> str:
    path = resource_path(filename)
    with open(path, 'r') as f:
        return f.read()

def text_resource_path(*parts: Sequence[str]) -> str:
    return resource_path("text", *parts) # type: ignore

def read_resource_text(*parts: Sequence[str]) -> str:
    return read_resource_file(os.path.join("text", *parts)) # type: ignore

def get_update_check_dates(new_date):
    from dateutil.parser import isoparse
    # This is the latest stable release date.
    release_date = isoparse(new_date).astimezone()
    # This is the rough date of the current release (might be stable or unstable).
    current_date = isoparse(PACKAGE_DATE).astimezone()
    return release_date, current_date

def get_identified_release_signers(entry):
    signature_addresses = [
        ("rt121212121", "1Bu6ABvLAXn1ARFo1gjq6sogpajGbp6iK6"),
        ("kyuupichan", "1BH8E3TkuJMCcH5WGD11kVweKZuhh6vb7V"),
    ]

    release_version = entry['version']
    release_date = entry['date']
    release_signatures = entry.get('signatures', [])

    message = release_version + release_date
    signed_names = set()
    for signature in release_signatures:
        for signer_name, signer_address in signature_addresses:
            if signer_name not in signed_names:
                # They are mainnet addresses
                if PublicKey.verify_message_and_address(signature, message, signer_address):
                    signed_names.add(signer_name)
                    break
    return signed_names


def chunks(items, size):
    '''Break up items, an iterable, into chunks of length size.'''
    for i in range(0, len(items), size):
        yield items[i: i + size]


class TriggeredCallbacks:
    def __init__(self) -> None:
        self._callbacks: Dict[str, List[Any]] = defaultdict(list)
        self._callback_lock = threading.Lock()
        self._callback_logger = logs.get_logger("callback-logger")

    def register_callback(self, callback: Any, events: List[str]) -> None:
        with self._callback_lock:
            for event in events:
                if callback in self._callbacks[event]:
                    self._callback_logger.error("Callback reregistered %s %s", event, callback)
                    continue
                self._callbacks[event].append(callback)

    def unregister_callback(self, callback) -> None:
        with self._callback_lock:
            for callbacks in self._callbacks.values():
                if callback in callbacks:
                    callbacks.remove(callback)

    def unregister_callbacks_for_object(self, owner: object) -> None:
        with self._callback_lock:
            for callbacks in self._callbacks.values():
                for callback in callbacks[:]:
                    if isinstance(callback, types.MethodType):
                        if callback.__self__ is owner:
                            callbacks.remove(callback)

    def trigger_callback(self, event: str, *args) -> None:
        with self._callback_lock:
            callbacks = self._callbacks[event][:]
        [callback(event, *args) for callback in callbacks]
