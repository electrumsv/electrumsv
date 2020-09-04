from decimal import Decimal
from concurrent.futures import CancelledError
import datetime
import decimal
import inspect
import json
import os
import requests
import sys
import time
from typing import Dict

from aiorpcx import ignore_after, run_in_thread

from .app_state import app_state
from .bitcoin import COIN
from .constants import NetworkEventNames
from .i18n import _
from .logs import logs
from .util import resource_path

logger = logs.get_logger("exchangerate")


# See https://en.wikipedia.org/wiki/ISO_4217
CCY_PRECISIONS = {'BHD': 3, 'BIF': 0, 'BYR': 0, 'CLF': 4, 'CLP': 0,
                  'CVE': 0, 'DJF': 0, 'GNF': 0, 'IQD': 3, 'ISK': 0,
                  'JOD': 3, 'JPY': 0, 'KMF': 0, 'KRW': 0, 'KWD': 3,
                  'LYD': 3, 'MGA': 1, 'MRO': 1, 'OMR': 3, 'PYG': 0,
                  'RWF': 0, 'TND': 3, 'UGX': 0, 'UYI': 0, 'VND': 0,
                  'VUV': 0, 'XAF': 0, 'XAU': 4, 'XOF': 0, 'XPF': 0}


class ExchangeBase(object):

    def __init__(self):
        self.history = {}
        self.quotes = {}

    def get_json(self, site, get_string):
        # APIs must have https
        url = ''.join(['https://', site, get_string])
        response = requests.request('GET', url, headers={'User-Agent' : 'ElectrumSV'}, timeout=10)
        return response.json()

    def name(self) -> str:
        return self.__class__.__name__

    async def update(self, ccy: str) -> None:
        try:
            logger.debug(f'getting fx quotes for {ccy}')
            self.quotes = await run_in_thread(self.get_rates, ccy)
            logger.debug('received fx quotes')
        except CancelledError:
            pass
        except requests.exceptions.ConnectionError as e:
            logger.error(f"unable to establish connection: {e}")
        except Exception:
            logger.exception('exception updating FX quotes')

    def get_rates(self, ccy) -> Dict:
        raise NotImplementedError()

    def read_historical_rates(self, ccy, cache_dir):
        filename = os.path.join(cache_dir, self.name() + '_'+ ccy)
        if os.path.exists(filename):
            timestamp = os.stat(filename).st_mtime
            try:
                with open(filename, 'r', encoding='utf-8') as f:
                    return json.loads(f.read()), timestamp
            except Exception:
                pass
        return None, None

    def _get_historical_rates(self, ccy, cache_dir):
        h, timestamp = self.read_historical_rates(ccy, cache_dir)
        if h is None or time.time() - timestamp < 24*3600:
            logger.debug(f'getting historical FX rates for {ccy}')
            h = self.request_history(ccy)
            logger.debug(f'received historical FX rates')
            filename = os.path.join(cache_dir, self.name() + '_' + ccy)
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(json.dumps(h))
        return h

    async def get_historical_rates(self, ccy, cache_dir):
        try:
            self.history[ccy] = await run_in_thread(self._get_historical_rates, ccy, cache_dir)
        except requests.exceptions.ConnectionError as e:
            logger.error(f"unable to establish connection {e}")
        except Exception:
            logger.exception('exception getting historical FX rates')

    def request_history(self, ccy):
        raise NotImplementedError()

    def refresh_historical_rates(self, ccy, cache_dir):
        result = self.history.get(ccy)
        if not result and ccy in self.history_ccys():
            self.get_historical_rates_safe(ccy, cache_dir)
            return True
        return False

    def history_ccys(self):
        return []

    def historical_rate(self, ccy, d_t):
        return self.history.get(ccy, {}).get(d_t.strftime('%Y-%m-%d'))

    def get_currencies(self):
        rates = self.get_rates('')
        return sorted([str(a) for (a, b) in rates.items() if b is not None and len(a)==3])


class BitPay(ExchangeBase):

    def get_rates(self, ccy):
        json = self.get_json('bitpay.com', '/api/rates/BSV')
        return dict([(r['code'], Decimal(r['rate'])) for r in json])


class Bitfinex(ExchangeBase):
    """
    https://docs.bitfinex.com/v2/reference
    """
    INDEX_SYMBOL = 0
    INDEX_BID = 1
    INDEX_BID_SIZE = 2
    INDEX_ASK = 3
    INDEX_ASK_SIZE = 4
    INDEX_DAILY_CHANGE = 5
    INDEX_DAILY_CHANGE_PERC = 6
    INDEX_LAST_PRICE = 7
    INDEX_VOLUME = 8
    INDEX_HIGH = 9
    INDEX_LOW = 10

    def get_rates(self, ccy):
        json_value = self.get_json('api.bitfinex.com', '/v2/tickers?symbols=tBSVUSD')
        if not isinstance(json_value, list) or not json_value:
            raise RuntimeError(f'bad Bitfinex rates: {json_value}')
        usd_entry = json_value[0]
        return {
            'USD': Decimal(usd_entry[Bitfinex.INDEX_LAST_PRICE]),
        }


class Coinbase(ExchangeBase):

    def get_rates(self, ccy):
        json = self.get_json('api.coinbase.com',
                             '/v2/exchange-rates?currency=BSV')
        return {ccy: Decimal(rate) for (ccy, rate) in json["data"]["rates"].items()}


class CoinFloor(ExchangeBase):
    # CoinFloor API only supports GBP on public API
    def get_rates(self, ccy):
        json = self.get_json('webapi.coinfloor.co.uk:8090/bist/BSV/GBP', '/ticker/')
        return {'GBP': Decimal(json['last'])}


class CoinPaprika(ExchangeBase):
    def get_rates(self, ccy):
        json = self.get_json('api.coinpaprika.com', '/v1/tickers/bsv-bitcoin-sv')
        return {'USD': Decimal(json['quotes']['USD']['price'])}

    def history_ccys(self):
        return ['USD']

    def request_history(self, ccy):
        limit = 1000
        end_date = datetime.date.today()
        start_date = end_date - datetime.timedelta(days=limit-1)
        history = self.get_json(
            'api.coinpaprika.com',
            "/v1/tickers/bsv-bitcoin-sv/historical?start={}&quote=USD&limit={}&interval=24h"
            .format(start_date.strftime("%Y-%m-%d"), limit))
        return dict([(datetime.datetime.strptime(
            h['timestamp'], '%Y-%m-%dT%H:%M:%SZ').strftime('%Y-%m-%d'), h['price'])
                     for h in history])


class CoinCap(ExchangeBase):
    def get_rates(self, ccy):
        json = self.get_json('api.coincap.io', '/v2/assets/bitcoin-sv')
        return {'USD': Decimal(json['data']['priceUsd'])}

    def history_ccys(self):
        return ['USD']

    def request_history(self, ccy):
        # Currently 2000 days is the maximum in 1 API call which needs to be fixed
        # sometime before the year 2023...
        history = self.get_json('api.coincap.io',
                               "/v2/assets/bitcoin-sv/history?interval=d1&limit=2000")
        return dict([(datetime.datetime.utcfromtimestamp(h['time']/1000).strftime('%Y-%m-%d'),
                        h['priceUsd'])
                     for h in history['data']])


class CoinGecko(ExchangeBase):

    def get_rates(self, ccy):
        json = self.get_json('api.coingecko.com',
                             '/api/v3/coins/bitcoin-cash-sv?localization=False&sparkline=false')
        prices = json["market_data"]["current_price"]
        return dict([(a[0].upper(),Decimal(a[1])) for a in prices.items()])

    def history_ccys(self):
        return ['AED', 'ARS', 'AUD', 'BTD', 'BHD', 'BMD', 'BRL', 'BTC',
                'CAD', 'CHF', 'CLP', 'CNY', 'CZK', 'DKK', 'ETH', 'EUR',
                'GBP', 'HKD', 'HUF', 'IDR', 'ILS', 'INR', 'JPY', 'KRW',
                'KWD', 'LKR', 'LTC', 'MMK', 'MXH', 'MYR', 'NOK', 'NZD',
                'PHP', 'PKR', 'PLN', 'RUB', 'SAR', 'SEK', 'SGD', 'THB',
                'TRY', 'TWD', 'USD', 'VEF', 'XAG', 'XAU', 'XDR', 'ZAR']

    def request_history(self, ccy):
        history = self.get_json(
            'api.coingecko.com',
            '/api/v3/coins/bitcoin-cash/market_chart?vs_currency=%s&days=max' % ccy)
        return dict([(datetime.datetime.utcfromtimestamp(h[0]/1000).strftime('%Y-%m-%d'), h[1])
                     for h in history['prices']])


def dictinvert(d):
    inv = {}
    for k, vlist in d.items():
        for v in vlist:
            keys = inv.setdefault(v, [])
            keys.append(k)
    return inv


def get_exchanges_and_currencies():
    path = resource_path('currencies.json')
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return json.loads(f.read())
    except Exception:
        pass
    d = {}
    is_exchange = lambda obj: (inspect.isclass(obj)
                               and issubclass(obj, ExchangeBase)
                               and obj != ExchangeBase)
    exchanges = dict(inspect.getmembers(sys.modules[__name__], is_exchange))
    for name, klass in exchanges.items():
        exchange = klass(None, None)
        try:
            d[name] = exchange.get_currencies()
            logger.debug("get_exchanges_and_currencies %s = ok", name)
        except Exception:
            logger.exception("get_exchanges_and_currencies %s = error", name)
            continue
    with open(path, 'w', encoding='utf-8') as f:
        f.write(json.dumps(d, indent=4, sort_keys=True))
    return d


CURRENCIES = get_exchanges_and_currencies()


def get_exchanges_by_ccy(history=True):
    if not history:
        return dictinvert(CURRENCIES)
    d = {}
    exchanges = CURRENCIES.keys()
    for name in exchanges:
        klass = globals()[name]
        exchange = klass()
        d[name] = exchange.history_ccys()
    return dictinvert(d)


class FxTask:

    def __init__(self, config, network):
        self.config = config
        self.network = network
        self.ccy = self.get_currency()
        self.fetch_history = False
        self.refresh_event = app_state.async_.event()
        self.history_used_spot = False
        self.ccy_combo = None
        self.hist_checkbox = None
        self.cache_dir = os.path.join(config.path, 'cache')
        self.set_exchange(self.config_exchange())
        if not os.path.exists(self.cache_dir):
            os.mkdir(self.cache_dir)

    def get_currencies(self):
        h = self.get_history_config()
        d = get_exchanges_by_ccy(h)
        return sorted(d.keys())

    def get_exchanges_by_ccy(self, ccy, h):
        d = get_exchanges_by_ccy(h)
        return d.get(ccy, [])

    def ccy_amount_str(self, amount, commas,default_prec = 2):
        prec = CCY_PRECISIONS.get(self.ccy, default_prec)
        fmt_str = "{:%s.%df}" % ("," if commas else "", max(0, prec))
        try:
            rounded_amount = round(amount, prec)
        except decimal.InvalidOperation:
            rounded_amount = amount
        return fmt_str.format(rounded_amount)

    async def refresh_loop(self):
        while True:
            async with ignore_after(150):
                await self.refresh_event.wait()
            self.refresh_event.clear()
            if not self.is_enabled():
                continue

            if self.fetch_history and self.show_history():
                self.fetch_history = False
                await self.exchange.get_historical_rates(self.ccy, self.cache_dir)
                if self.network:
                    self.network.trigger_callback(NetworkEventNames.HISTORICAL_EXCHANGE_RATES)

            await self.exchange.update(self.ccy)
            if self.network:
                self.network.trigger_callback(NetworkEventNames.EXCHANGE_RATE_QUOTES)

    def is_enabled(self):
        return bool(self.config.get('use_exchange_rate'))

    def set_enabled(self, enabled):
        return self.config.set_key('use_exchange_rate', enabled)

    def get_history_config(self):
        return bool(self.config.get('history_rates'))

    def set_history_config(self, enabled):
        self.config.set_key('history_rates', enabled)
        if self.is_enabled() and enabled:
            self.trigger_history_refresh()

    def get_fiat_address_config(self):
        return bool(self.config.get('fiat_address'))

    def set_fiat_address_config(self, b):
        self.config.set_key('fiat_address', b)

    def get_currency(self):
        '''Use when dynamic fetching is needed'''
        return self.config.get("currency", "EUR")

    def config_exchange(self):
        return self.config.get('use_exchange', 'CoinGecko')

    def show_history(self):
        return (self.is_enabled() and self.get_history_config() and
                self.ccy in self.exchange.history_ccys())

    def trigger_history_refresh(self):
        self.fetch_history = True
        self.refresh_event.set()

    def set_currency(self, ccy):
        if self.get_currency() != ccy:
            self.ccy = ccy
            self.config.set_key('currency', ccy, True)
            self.trigger_history_refresh()

    def set_exchange(self, name):
        class_ = globals().get(name, CoinGecko)
        logger.debug("using exchange %s", name)
        if self.config_exchange() != name:
            self.config.set_key('use_exchange', name, True)
        self.exchange = class_()
        # A new exchange means new fx quotes, initially empty.
        self.trigger_history_refresh()

    def exchange_rate(self):
        '''Returns None, or the exchange rate as a Decimal'''
        rate = self.exchange.quotes.get(self.ccy)
        if rate:
            return Decimal(rate)

    def format_amount_and_units(self, btc_balance):
        amount_str = self.format_amount(btc_balance)
        return '' if not amount_str else "%s %s" % (amount_str, self.ccy)

    def format_amount(self, btc_balance):
        rate = self.exchange_rate()
        return '' if rate is None else self.value_str(btc_balance, rate)

    def get_fiat_status(self, btc_balance, base_unit, decimal_point):
        rate = self.exchange_rate()
        if rate is None:
            return None, None
        default_prec = 2
        if base_unit == "bits":
            default_prec = 4
        bitcoin_value = f"1 {base_unit}"
        fiat_value = (f"{self.value_str(COIN / (10**(8 - decimal_point)), rate, default_prec )} "+
            f"{self.ccy}")
        return bitcoin_value, fiat_value

    def value_str(self, satoshis, rate, default_prec = 2 ):
        if satoshis is None:  # Can happen with incomplete history
            return _("Unknown")
        if rate:
            value = Decimal(satoshis) / COIN * Decimal(rate)
            return "%s" % (self.ccy_amount_str(value, True, default_prec))
        return _("No data")

    def history_rate(self, d_t):
        rate = self.exchange.historical_rate(self.ccy, d_t)
        # Frequently there is no rate for today, until tomorrow :)
        # Use spot quotes in that case
        if rate is None and (datetime.datetime.today().date() - d_t.date()).days <= 2:
            rate = self.exchange.quotes.get(self.ccy)
            self.history_used_spot = True
        return Decimal(rate) if rate is not None else None

    def historical_value_str(self, satoshis, d_t):
        rate = self.history_rate(d_t)
        return self.value_str(satoshis, rate)

    def historical_value(self, satoshis, d_t):
        rate = self.history_rate(d_t)
        if rate:
            return Decimal(satoshis) / COIN * Decimal(rate)

    def timestamp_rate(self, timestamp):
        from .util import timestamp_to_datetime
        date = timestamp_to_datetime(timestamp)
        return self.history_rate(date)
