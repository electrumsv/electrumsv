# Electrum - lightweight Bitcoin client
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

from __future__ import annotations
from decimal import Decimal
import random
import re
from typing import Any, Dict, Iterable, List, Optional, TYPE_CHECKING
import urllib
import urllib.parse

from bitcoinx import Address

from .bip276 import PREFIX_BIP276_SCRIPT, bip276_decode, NetworkMismatchError, ChecksumMismatchError
from .bitcoin import COIN, is_address_valid
from .i18n import _
from .logs import logs
from .networks import Net
from .util import format_satoshis_plain

if TYPE_CHECKING:
    from .simple_config import SimpleConfig


logger = logs.get_logger("web")


def BE_from_config(config: "SimpleConfig") -> str:
    return config.get_explicit_type(str, 'block_explorer', '')


def random_BE(kind: Optional[str]=None) -> Optional[str]:
    possible_keys: List[str] = [ k for (k, v) in Net.BLOCK_EXPLORERS.items()
        if k != "system default" and (kind is None or v[1].get(kind) is not None) ]
    if len(possible_keys):
        return random.choice(possible_keys)
    return None


def BE_URL(config: "SimpleConfig", kind: str, item: str) -> Optional[str]:
    selected_key: Optional[str] = BE_from_config(config)
    if selected_key is None or selected_key not in Net.BLOCK_EXPLORERS:
        selected_key = random_BE(kind)
    be_tuple = Net.BLOCK_EXPLORERS.get(selected_key)
    if not be_tuple:
        return None
    url_base, parts = be_tuple
    kind_str = parts.get(kind)
    if kind_str is None:
        return None
    if kind == 'addr':
        assert isinstance(item, Address)
        item = item.to_string()
    return "/".join(part for part in (url_base, kind_str, item) if part)


def BE_sorted_list() -> Iterable[str]:
    return sorted(Net.BLOCK_EXPLORERS)


def create_URI(dest: str, amount: Optional[int], message: str) -> str:
    scheme = Net.BITCOIN_URI_PREFIX
    query_parts = ['sv']
    scheme_idx = dest.find(":")
    if scheme_idx != -1:
        scheme = dest[:scheme_idx]
        dest = dest[scheme_idx+1:]
        query_parts = []
    if amount:
        query_parts.append('amount=%s'%format_satoshis_plain(amount))
    if message:
        query_parts.append('message=%s'%urllib.parse.quote(message))
    query_string = ""
    if len(query_parts):
        query_string = '&'.join(query_parts)
    p = urllib.parse.ParseResult(scheme=scheme, netloc='', path=dest,
        params='', query=query_string, fragment='')
    return urllib.parse.urlunparse(p)


def is_URI(text: str) -> bool:
    '''Returns true if the text looks like a URI.  It is not validated, and is not checked to
    be a Bitcoin SV URI.
    '''
    scheme_idx = text.find(":")
    if scheme_idx > -1:
        scheme = text[:scheme_idx].lower()
        if scheme in (Net.BITCOIN_URI_PREFIX, "pay") or scheme == PREFIX_BIP276_SCRIPT:
            return True
    return False


class URIError(Exception):
    pass



def parse_pay_url(url: str) -> tuple[str, Address]:
    parsed_url = urllib.parse.urlparse(url)
    if parsed_url.scheme != "pay":
        raise ValueError("The URL does not have the 'pay' scheme")

    # NOTE(rt12) This is currently direct payment specific. It may not always be.
    parsed_query = urllib.parse.parse_qs(parsed_url.query, keep_blank_values=True)
    if "r" not in parsed_query:
        raise ValueError("The URL does not have a payment URL")
    payment_url = parsed_query["r"][0]
    url_parts = payment_url.rsplit("/", 1)
    if len(url_parts) != 2:
        raise ValueError("The URL has no usable credentials")

    # The last section of the query string is the payment id, and this is expected to be usable
    # to validate the fetched payment terms come from the same party.
    return payment_url, Address.from_string(url_parts[1], Net.COIN)


def parse_URI(uri: str) -> dict[str, Any]:
    if is_address_valid(uri):
        return {'address': uri}

    u = urllib.parse.urlparse(uri)

    # The scheme always comes back in lower case
    pq = urllib.parse.parse_qs(u.query, keep_blank_values=True)
    if not (u.scheme == Net.BITCOIN_URI_PREFIX and 'sv' in pq or
            u.scheme in (PREFIX_BIP276_SCRIPT, "pay")):
        raise URIError(_('Invalid Bitcoin SV URI: {}').format(uri))

    for k, v in pq.items():
        if len(v) != 1:
            raise URIError(_('Duplicate query key {0} in BitcoinSV URI {1}').format(k, uri))

    out: Dict[str, Any] = {k: v[0] for k, v in pq.items()}

    if u.scheme == Net.BITCOIN_URI_PREFIX and is_address_valid(u.path):
        out['address'] = u.path
    elif u.scheme == PREFIX_BIP276_SCRIPT:
        try:
            _prefix, _version, _data_network, bip276_data = bip276_decode(u.scheme +":"+ u.path,
                Net.BIP276_VERSION)
            out['script'] = bip276_data
            out['bip276'] = f"{u.scheme}:{u.path}"
        except NetworkMismatchError:
            pass
        except ChecksumMismatchError:
            pass

    if 'amount' in out:
        am = out['amount']
        m = re.match(r'([0-9\.]+)X([0-9])', am)
        if m:
            ak = int(m.group(2)) - 8
            amount = Decimal(m.group(1)) * pow(10, ak)
        else:
            amount = Decimal(am) * COIN
        out['amount'] = int(amount)
    if 'message' in out:
        out['message'] = out['message']
        out['memo'] = out['message']
    if 'time' in out:
        out['time'] = int(out['time'])
    if 'exp' in out:
        out['exp'] = int(out['exp'])

    return out
