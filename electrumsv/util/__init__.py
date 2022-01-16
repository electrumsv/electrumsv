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
from datetime import datetime, timedelta, tzinfo
import json
import hmac
import os
import stat
import sys
import threading
import time
import types
from typing import Any, Callable, cast, Dict, Iterable, List, Optional, Sequence, Set, Tuple, \
    TypedDict, TypeVar, Union

from bitcoinx import PublicKey

from ..logs import logs
from ..startup import package_dir
from ..types import ExceptionInfoType
from ..version import PACKAGE_DATE


T1 = TypeVar("T1")


def protocol_tuple(s: str) -> Tuple[int, ...]:
    '''Converts a protocol version number, such as "1.0" to a tuple (1, 0).

    If the version number is bad, (0, ) indicating version 0 is returned.'''
    try:
        return tuple(int(part) for part in s.split('.'))
    except (TypeError, ValueError, AttributeError):
        raise ValueError(f'invalid protocol version: {s}') from None


def version_string(ptuple: Tuple[int, ...]) -> str:
    '''Convert a version tuple such as (1, 2) to "1.2".
    There is always at least one dot, so (1, ) becomes "1.0".'''
    while len(ptuple) < 2:
        ptuple += (0, )
    return '.'.join(str(p) for p in ptuple)


class MyEncoder(json.JSONEncoder):
    # https://github.com/PyCQA/pylint/issues/414
    def default(self, o: Any) -> Any: # pylint: disable=method-hidden
        from ..transaction import Transaction, TransactionContext
        if isinstance(o, Transaction):
            return o.to_dict(TransactionContext())
        return super(MyEncoder, self).default(o)


class JSON:
    classes: Dict[str, Any] = {}

    @classmethod
    def register(cls, *classes: Any) -> None:
        for klass in classes:
            cls.classes[klass.__name__] = klass

    @classmethod
    def dumps(cls, obj: Any, **kwargs: Any) -> str:
        def encode_obj(obj: Any) -> Dict[str, Any]:
            class_name = obj.__class__.__name__
            if class_name not in cls.classes:
                raise TypeError(f'object of type {class_name} is not JSON serializable')
            return {'_sv': (class_name, obj.to_json())}

        kwargs['default'] = encode_obj
        return json.dumps(obj, **kwargs)

    @classmethod
    def loads(cls, s: Union[str, bytes], **kwargs: Any) -> Any:
        def decode_obj(obj: Dict[str, Any]) -> Any:
            if '_sv' in obj:
                class_name, ser = obj['_sv']
                obj = cls.classes[class_name].from_json(ser)
            return obj

        kwargs['object_hook'] = decode_obj
        return json.loads(s, **kwargs)


class DaemonThread(threading.Thread):
    """ daemon thread that terminates cleanly """

    def __init__(self, name: str) -> None:
        threading.Thread.__init__(self)
        self.name = name
        self.parent_thread = threading.current_thread()
        self.running = False
        self.running_lock = threading.Lock()
        self.logger = logs.get_logger(f'{name} thread')

    def start(self) -> None:
        with self.running_lock:
            self.running = True
        threading.Thread.start(self)

    def is_running(self) -> bool:
        with self.running_lock:
            return self.running and self.parent_thread.is_alive()

    def stop(self) -> None:
        with self.running_lock:
            self.running = False

    def on_stop(self) -> None:
        self.logger.debug("stopped")


def json_encode(obj: Any) -> str:
    try:
        s = json.dumps(obj, sort_keys = True, indent = 4, cls=MyEncoder)
    except TypeError:
        s = repr(obj)
    return s

def json_decode(x: Union[str, bytes]) -> Any:
    try:
        return json.loads(x, parse_float=Decimal)
    except Exception:
        return x


# taken from Django Source Code
def constant_time_compare(val1: str, val2: str) -> bool:
    """Return True if the two strings are equal, False otherwise."""
    return hmac.compare_digest(val1.encode('utf8'), val2.encode('utf8'))


# decorator that prints execution time
def profiler(func: Callable[..., T1]) -> Callable[..., T1]:
    def do_profile(func: Callable[..., T1], args: Tuple[Any, ...], kw_args: Dict[str, Any]) -> T1:
        n = func.__name__
        logger = logs.get_logger("profiler")
        t0 = time.time()
        o = func(*args, **kw_args)
        t = time.time() - t0
        logger.debug("%s %.8f", n, t)
        return o
    return lambda *args, **kw_args: do_profile(func, args, kw_args)


def assert_datadir_available(config_path: str) -> None:
    path = config_path
    if os.path.exists(path):
        return
    else:
        raise FileNotFoundError(
            'ElectrumSV datadir does not exist. Was it deleted while running?' + '\n' +
            'Should be at {}'.format(path))


def make_dir(path: str) -> None:
    # Make directory if it does not yet exist.
    if not os.path.exists(path):
        if os.path.islink(path):
            raise Exception('Dangling link: ' + path)
        os.mkdir(path)
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)


def format_satoshis_plain(x: int, decimal_point: int=8) -> str:
    """Display a satoshi amount scaled.  Always uses a '.' as a decimal
    point and has no thousands separator"""
    scale_factor = pow(10, decimal_point)
    return "{:.8f}".format(Decimal(x) / scale_factor).rstrip('0').rstrip('.')


def format_satoshis(x: Optional[int], num_zeros: int=0, decimal_point: int=8,
        precision: Optional[int]=None,
        is_diff: bool=False, whitespaces: bool=False) -> str:
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


def format_fee_satoshis(fee: int, num_zeros: int=0) -> str:
    return format_satoshis(fee, num_zeros, 0, precision=num_zeros)


def get_posix_timestamp() -> int:
    # In theory we can just return `int(time.time())` but this returns the posix timestamp and
    # try reading the documentation for `time.time` and being sure of that.
    return int(datetime.now().timestamp())


def posix_timestamp_to_datetime(timestamp: int) -> datetime:
    "Get a local timezone unaware datetime object for the given posix timestamp."
    return datetime.fromtimestamp(timestamp)


def format_posix_timestamp(timestamp: int, default_text: str) -> str:
    "Get the date and time for the given posix timestamp."
    date = posix_timestamp_to_datetime(timestamp)
    if date:
        return date.isoformat(' ')[:16]
    return default_text


# Takes a timestamp and returns a string with the approximation of the age
def age(from_timestamp: Optional[float], since_date: Optional[datetime]=None,
        target_tz: Optional[tzinfo]=None, include_seconds: bool=False) -> str:
    if from_timestamp is None:
        return "Unknown"

    from_date = datetime.fromtimestamp(from_timestamp)
    if since_date is None:
        since_date = datetime.now(target_tz)

    td = time_difference(from_date - since_date, include_seconds)
    return td + " ago" if from_date < since_date else "in " + td


def time_difference(distance_in_time: timedelta, include_seconds: bool) -> str:
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


def setup_thread_excepthook() -> None:
    """
    Workaround for `sys.excepthook` thread bug from:
    http://bugs.python.org/issue1230540

    Call once from the main thread before creating any threads.
    """

    init_original = threading.Thread.__init__

    def init(self: threading.Thread, *args: Any, **kwargs: Any) -> None:
        init_original(self, *args, **kwargs)
        run_original = self.run

        def run_with_except_hook() -> None:
            try:
                run_original()
            except Exception:
                sys.excepthook(*sys.exc_info())

        # NOTE(typing) mypy tells us we cannot assign to a method, but we really can and do..
        self.run = run_with_except_hook # type: ignore

    # NOTE(typing) mypy tells us we cannot assign to a method, but we really can and do..
    threading.Thread.__init__ = init # type: ignore


def get_wallet_name_from_path(wallet_path: str) -> str:
    return os.path.splitext(os.path.basename(wallet_path))[0]


def versiontuple(v: str) -> Tuple[int, ...]:
    return tuple(int(x) for x in v.split("."))


def resource_path(*parts: Sequence[str]) -> str:
    return os.path.join(package_dir, "data", *parts) # type: ignore


def read_resource_file(filename: str) -> str:
    path = resource_path(filename)
    with open(path, 'r') as f:
        return f.read()


def text_resource_path(*parts: Sequence[str]) -> str:
    return resource_path("text", *parts)



def read_resource_text(*parts: Sequence[str]) -> str:
    # NOTE(typing) Does not recognize the sequence of strings as strings, waste of time.
    return read_resource_file(os.path.join("text", *parts)) # type:ignore



def get_update_check_dates(new_date: str) -> Tuple[datetime, datetime]:
    from dateutil.parser import isoparse
    # This is the latest stable release date.
    release_date = isoparse(new_date).astimezone()
    # This is the rough date of the current release (might be stable or unstable).
    current_date = isoparse(PACKAGE_DATE).astimezone()
    return release_date, current_date


class ReleaseEntryType(TypedDict):
    version: str
    date: str
    signatures: List[str]


class ReleaseDocumentType(TypedDict, total=False):
    stable: ReleaseEntryType
    unstable: ReleaseEntryType


UpdateCheckResultType = Union[ExceptionInfoType, ReleaseDocumentType]


def get_identified_release_signers(entry: ReleaseEntryType) -> Set[str]:
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


def chunks(items: List[T1], size: int) -> Iterable[List[T1]]:
    '''Break up items, an iterable, into chunks of length size.'''
    for i in range(0, len(items), size):
        yield items[i: i + size]


class TriggeredCallbacks:
    def __init__(self) -> None:
        self._callbacks: Dict[str, List[Callable[..., None]]] = defaultdict(list)
        self._callback_lock = threading.Lock()
        self._callback_logger = logs.get_logger("callback-logger")

    def register_callback(self, callback: Callable[..., None], events: List[str]) -> None:
        with self._callback_lock:
            for event in events:
                if callback in self._callbacks[event]:
                    self._callback_logger.error("Callback reregistered %s %s", event, callback)
                    continue
                self._callbacks[event].append(callback)

    def unregister_callback(self, callback: Callable[..., None]) -> None:
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

    def trigger_callback(self, event: str, *args: Any) -> None:
        with self._callback_lock:
            callbacks = self._callbacks[event][:]
        [callback(event, *args) for callback in callbacks]


class ValueLocks:
    def __init__(self) -> None:
        self._namespace_lock = threading.Lock()
        self._namespace: Dict[Any, threading.RLock] = {}
        self._counters: Dict[Any, int] = {}

    def acquire_lock(self, value: Any) -> None:
        with self._namespace_lock:
            if value in self._namespace:
                self._counters[value] += 1
            else:
                self._namespace[value] = threading.RLock()
                self._counters[value] = 1

        self._namespace[value].acquire()

    def release_lock(self, value: Any) -> None:
        with self._namespace_lock:
            if self._counters[value] == 1:
                del self._counters[value]
                lock = self._namespace.pop(value)
            else:
                self._counters[value] -= 1
                lock = self._namespace[value]

        lock.release()