#!/usr/bin/env python
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2015 kyuupichan@gmail
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

from collections import defaultdict, namedtuple
from math import floor, log10

from bitcoinx import sha256

from .bitcoin import COIN
from .logs import logs
from .transaction import Transaction, XTxOutput
from .exceptions import NotEnoughFunds


logger = logs.get_logger("coinchooser")


# A simple deterministic PRNG.  Used to deterministically shuffle a
# set of coins - the same set of coins should produce the same output.
# Although choosing UTXOs "randomly" we want it to be deterministic,
# so if sending twice from the same UTXO set we choose the same UTXOs
# to spend.  This prevents attacks on users by malicious or stale
# servers.
class PRNG:
    def __init__(self, seed):
        self.sha = sha256(seed)
        self.pool = bytearray()

    def get_bytes(self, n):
        while len(self.pool) < n:
            self.pool.extend(self.sha)
            self.sha = sha256(self.sha)
        result, self.pool = self.pool[:n], self.pool[n:]
        return result

    def randint(self, start, end):
        # Returns random integer in [start, end)
        n = end - start
        r = 0
        p = 1
        while p < n:
            r = self.get_bytes(1)[0] + (r << 8)
            p = p << 8
        return start + (r % n)

    def choice(self, seq):
        return seq[self.randint(0, len(seq))]

    def shuffle(self, x):
        for i in reversed(range(1, len(x))):
            # pick an element in x[:i+1] with which to exchange x[i]
            j = self.randint(0, i+1)
            x[i], x[j] = x[j], x[i]


Bucket = namedtuple('Bucket', ['desc', 'size', 'value', 'coins'])

def strip_unneeded(bkts, sufficient_funds):
    '''Remove buckets that are unnecessary in achieving the spend amount'''
    bkts = sorted(bkts, key = lambda bkt: bkt.value)
    for i in range(len(bkts)):
        if not sufficient_funds(bkts[i + 1:]):
            return bkts[i:]
    # Shouldn't get here
    return bkts

class CoinChooserBase:
    def keys(self, coins):
        raise NotImplementedError

    def bucketize_coins(self, coins):
        keys = self.keys(coins)
        buckets = defaultdict(list)
        for key, coin in zip(keys, coins):
            buckets[key].append(coin)

        def make_Bucket(desc, coins):
            size = sum(coin.estimated_size() for coin in coins)
            value = sum(coin.value for coin in coins)
            return Bucket(desc, size, value, coins)

        return [make_Bucket(key, value) for key, value in buckets.items()]

    def penalty_func(self, _tx):
        def penalty(_candidate):
            return 0
        return penalty

    def change_amounts(self, tx, count, fee_estimator, _dust_threshold):
        # Break change up if bigger than max_change
        output_amounts = [output.value for output in tx.outputs]
        # Don't split change of less than 0.02 BTC
        max_change = max(max(output_amounts) * 1.25, 0.02 * COIN)

        # Use N change outputs
        for n in range(1, count + 1):
            # How much is left if we add this many change outputs?
            change_amount = max(0, tx.get_fee() - fee_estimator(n))
            if change_amount // n <= max_change:
                break

        # Get a handle on the precision of the output amounts; round our
        # change to look similar
        def trailing_zeroes(val):
            s = str(val)
            return len(s) - len(s.rstrip('0'))

        zeroes = [trailing_zeroes(i) for i in output_amounts]
        min_zeroes = min(zeroes)
        max_zeroes = max(zeroes)
        zeroes = range(max(0, min_zeroes - 1), (max_zeroes + 1) + 1)

        # Calculate change; randomize it a bit if using more than 1 output
        remaining = change_amount
        amounts = []
        while n > 1:
            average = remaining / n
            amount = self.p.randint(int(average * 0.7), int(average * 1.3))
            precision = min(self.p.choice(zeroes), int(floor(log10(amount))))
            amount = int(round(amount, -precision))
            amounts.append(amount)
            remaining -= amount
            n -= 1

        # Last change output.  Round down to maximum precision but lose
        # no more than 100 satoshis to fees (2dp)
        N = pow(10, min(2, zeroes[0]))
        amount = (remaining // N) * N
        amounts.append(amount)

        assert sum(amounts) <= change_amount

        return amounts

    def change_outputs(self, tx, change_outs, fee_estimator, dust_threshold):
        amounts = self.change_amounts(tx, len(change_outs), fee_estimator, dust_threshold)
        assert min(amounts) >= 0
        assert len(change_outs) >= len(amounts)
        # If change is above dust threshold after accounting for the
        # size of the change output, add it to the transaction.
        dust = sum(amount for amount in amounts if amount < dust_threshold)
        amounts = [amount for amount in amounts if amount >= dust_threshold]
        change = [XTxOutput(amount, out.script_pubkey, out.script_type, out.x_pubkeys)
                  for out, amount in zip(change_outs, amounts)]
        logger.debug('change %s', change)
        if dust:
            logger.debug('not keeping dust %s', dust)
        return change, dust

    def make_tx(self, coins, outputs, change_outs, fee_estimator, dust_threshold):
        '''Select unspent coins to spend to pay outputs.  If the change is
        greater than dust_threshold (after adding the change output to
        the transaction) it is kept, otherwise none is sent and it is
        added to the transaction fee.'''

        # Deterministic randomness from coins
        self.p = PRNG(b''.join(sorted(c.prevout_bytes() for c in coins)))

        # Copy the ouputs so when adding change we don't modify "outputs"
        tx = Transaction.from_io([], outputs)
        # Size of the transaction with no inputs and no change
        base_size = tx.estimated_size()
        spent_amount = tx.output_value()

        def sufficient_funds(buckets):
            '''Given a list of buckets, return True if it has enough
            value to pay for the transaction'''
            total_input = sum(bucket.value for bucket in buckets)
            total_size = sum(bucket.size for bucket in buckets) + base_size
            return total_input >= spent_amount + fee_estimator(total_size)

        # Collect the coins into buckets, choose a subset of the buckets
        buckets = self.bucketize_coins(coins)
        buckets = self.choose_buckets(buckets, sufficient_funds,
                                      self.penalty_func(tx))

        tx.inputs.extend(coin for b in buckets for coin in b.coins)
        tx_size = base_size + sum(bucket.size for bucket in buckets)

        # This takes a count of change outputs and returns a tx fee;
        # each pay-to-bitcoin-address output serializes as 34 bytes
        fee = lambda count: fee_estimator(tx_size + count * 34)
        change, dust = self.change_outputs(tx, change_outs, fee, dust_threshold)
        tx.outputs.extend(change)

        logger.debug("using %d inputs", len(tx.inputs))
        logger.debug("using buckets: %s", [bucket.desc for bucket in buckets])

        return tx

    def choose_buckets(self, buckets, sufficient_funds, penalty_func):
        raise NotImplementedError('To be subclassed')

class CoinChooserRandom(CoinChooserBase):

    def bucket_candidates(self, buckets, sufficient_funds):
        '''Returns a list of bucket sets.'''
        candidates = set()

        # Add all singletons
        for n, bucket in enumerate(buckets):
            if sufficient_funds([bucket]):
                candidates.add((n, ))

        # And now some random ones
        attempts = min(100, (len(buckets) - 1) * 10 + 1)
        permutation = list(range(len(buckets)))
        for _i in range(attempts):
            # Get a random permutation of the buckets, and
            # incrementally combine buckets until sufficient
            self.p.shuffle(permutation)
            bkts = []
            for count, index in enumerate(permutation):
                bkts.append(buckets[index])
                if sufficient_funds(bkts):
                    candidates.add(tuple(sorted(permutation[:count + 1])))
                    break
            else:
                raise NotEnoughFunds()

        candidates = [[buckets[n] for n in c] for c in candidates]
        return [strip_unneeded(c, sufficient_funds) for c in candidates]

    def choose_buckets(self, buckets, sufficient_funds, penalty_func):
        candidates = self.bucket_candidates(buckets, sufficient_funds)
        penalties = [penalty_func(cand) for cand in candidates]
        winner = candidates[penalties.index(min(penalties))]
        logger.debug("Bucket sets: %d", len(buckets))
        logger.debug("Winning penalty: %d", min(penalties))
        return winner

class CoinChooserPrivacy(CoinChooserRandom):
    '''Attempts to better preserve user privacy.  First, if any coin is spent from a user
    address, all coins are.  Compared to spending from other addresses to make up an
    amount, this reduces information leakage about sender holdings.  It also helps to
    reduce future privacy loss that would come from reusing that address' remaining UTXOs.
    Second, it penalizes change that is quite different to the sent amount.  Third, it
    penalizes change that is too big.
    '''

    def keys(self, coins):
        return [coin.keyinstance_id for coin in coins]

    def penalty_func(self, tx):
        out_values = [output.value for output in tx.outputs]
        max_change = max(out_values) * 1.5
        spent_amount = sum(out_values)

        def penalty(buckets):
            badness = len(buckets) - 1
            total_input = sum(bucket.value for bucket in buckets)
            change = float(total_input - spent_amount)
            # Penalize change not roughly in output range
            if change > max_change:
                badness += (change - max_change) / (max_change + 10000)
                # Penalize large change; 5 BSV excess ~= using 1 more input
                badness += change / (COIN * 5)
            return badness

        return penalty
