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

from collections import defaultdict
from math import floor, log10
from typing import Any, Callable, cast, Dict, List, NamedTuple, Sequence, Set, Tuple, TypeVar

from bitcoinx import sha256

from .bitcoin import COIN
from .logs import logs
from .transaction import Transaction, XTxInput, XTxOutput
from .types import TransactionFeeEstimator, TransactionSize
from .exceptions import NotEnoughFunds


T = TypeVar("T")


logger = logs.get_logger("coinchooser")


class Bucket(NamedTuple):
    desc: int
    size: TransactionSize
    value: int
    coins: List[XTxInput]

ScaledFeeEstimator = Callable[[int], int]
SufficientFundsCheck = Callable[[List[Bucket]], bool]
BucketPenaltyFunction = Callable[[List[Bucket]], float]


# A simple deterministic PRNG.  Used to deterministically shuffle a
# set of coins - the same set of coins should produce the same output.
# Although choosing UTXOs "randomly" we want it to be deterministic,
# so if sending twice from the same UTXO set we choose the same UTXOs
# to spend.  This prevents attacks on users by malicious or stale
# servers.
class PRNG:
    def __init__(self, seed: bytes) -> None:
        self.sha = sha256(seed)
        self.pool = bytearray()

    def get_bytes(self, n: int) -> bytes:
        while len(self.pool) < n:
            self.pool.extend(self.sha)
            self.sha = sha256(self.sha)
        result, self.pool = self.pool[:n], self.pool[n:]
        return result

    def randint(self, start: int, end: int) -> int:
        # Returns random integer in [start, end)
        n = end - start
        r = 0
        p = 1
        while p < n:
            r = self.get_bytes(1)[0] + (r << 8)
            p = p << 8
        return start + (r % n)

    def choice(self, seq: Sequence[T]) -> T:
        return seq[self.randint(0, len(seq))]

    def shuffle(self, x: List[Any]) -> None:
        for i in reversed(range(1, len(x))):
            # pick an element in x[:i+1] with which to exchange x[i]
            j = self.randint(0, i+1)
            x[i], x[j] = x[j], x[i]

    def pluck(self, seq: List[T]) -> T:
        return seq.pop(self.randint(0, len(seq)))


def strip_unneeded_coins(bkts: List[Bucket], sufficient_funds: SufficientFundsCheck) \
        -> List[Bucket]:
    '''Remove buckets that are unnecessary in achieving the spend amount'''
    bkts = sorted(bkts, key = lambda bkt: bkt.value)
    for i in range(len(bkts)):
        if not sufficient_funds(bkts[i + 1:]):
            return bkts[i:]
    # Shouldn't get here
    return bkts


class CoinChooserBase:
    def keys(self, coins: List[XTxInput]) -> List[int]:
        # We do not care about privacy if people reuse keys. So the key for a bucket of coins is
        # the database `keyinstance_id`.
        coin_keyinstance_ids = [ c.x_pubkeys[0].derivation_data.keyinstance_id for c in coins ]
        assert all(isinstance(coin_keyinstance_id, int)
            for coin_keyinstance_id in coin_keyinstance_ids)
        return cast(List[int], coin_keyinstance_ids)

    def bucketize_coins(self, coins: List[XTxInput]) -> List[Bucket]:
        buckets: Dict[int, List[XTxInput]] = defaultdict(list)
        for keyinstance_id, coin in zip(self.keys(coins), coins):
            buckets[keyinstance_id].append(coin)

        def make_Bucket(desc: int, coins: List[XTxInput]) -> Bucket:
            size = sum(coin.estimated_size() for coin in coins)
            # NOTE(typing) Fix correct but broken error about not being able to sum optional values.
            # `error: Value of type variable "_SumT" of "sum" cannot be "Optional[int]"  [type-var]`
            # Changing it to `cast(int, coin.value)` yields the following:
            # `error: Redundant cast to "int"  [redundant-cast]`
            value = sum(coin.value for coin in coins) # type: ignore[type-var]
            return Bucket(desc, cast(TransactionSize, size), cast(int, value), coins)

        return [make_Bucket(key, value) for key, value in buckets.items()]

    def create_penalty_function(self, _tx: Transaction) -> BucketPenaltyFunction:
        def penalty(_candidates: List[Bucket]) -> float:
            return 0.0
        return penalty

    def change_amounts(self, tx: Transaction, maximum_change_count: int,
            change_fee_scaler: ScaledFeeEstimator, _dust_threshold: int) -> List[int]:
        # Break change up if bigger than max_change
        output_amounts = [output.value for output in tx.outputs]
        # Don't split change of less than 0.02 BTC
        max_change = max(max(output_amounts) * 1.25, 0.02 * COIN)

        # Use N change outputs
        change_amount = 0
        used_change_count = 0
        for used_change_count in range(1, maximum_change_count + 1):
            # How much is left if we add this many change outputs?
            change_amount = max(0, tx.get_fee() - change_fee_scaler(used_change_count))
            if change_amount // used_change_count <= max_change:
                break

        # Get a handle on the precision of the output amounts; round our
        # change to look similar
        def trailing_zeroes(val: int) -> int:
            s = str(val)
            return len(s) - len(s.rstrip('0'))

        zeroes: Sequence[int] = [trailing_zeroes(i) for i in output_amounts]
        min_zeroes = min(zeroes)
        max_zeroes = max(zeroes)
        zeroes = range(max(0, min_zeroes - 1), (max_zeroes + 1) + 1)

        # Calculate change; randomize it a bit if using more than 1 output
        remaining = change_amount
        amounts = []
        while used_change_count > 1:
            average = remaining / used_change_count
            amount = self.p.randint(int(average * 0.7), int(average * 1.3))
            precision = min(self.p.choice(zeroes), int(floor(log10(amount))))
            amount = int(round(amount, -precision))
            amounts.append(amount)
            remaining -= amount
            used_change_count -= 1

        # Last change output.  Round down to maximum precision but lose
        # no more than 100 satoshis to fees (2dp)
        N = pow(10, min(2, zeroes[0]))
        amount = (remaining // N) * N
        amounts.append(amount)
        assert sum(amounts) <= change_amount
        return amounts

    def change_outputs(self, tx: Transaction, available_change_outputs: List[XTxOutput],
            change_fee_scaler: ScaledFeeEstimator, dust_threshold: int) \
                -> Tuple[List[XTxOutput], int]:
        amounts = self.change_amounts(tx, len(available_change_outputs), change_fee_scaler,
            dust_threshold)
        assert min(amounts) >= 0
        assert len(available_change_outputs) >= len(amounts)
        # If change is above dust threshold after accounting for the
        # size of the change output, add it to the transaction.
        dust = sum(amount for amount in amounts if amount < dust_threshold)
        amounts = [amount for amount in amounts if amount >= dust_threshold]
        change = [
            # NOTE(typing) attrs/pylance fails to identify params from TxOutput base class.
            XTxOutput(amount, out.script_pubkey, out.script_type, out.x_pubkeys) # type: ignore
            for out, amount in zip(available_change_outputs, amounts)
        ]
        logger.debug('change %s', change)
        if dust:
            logger.debug('not keeping dust %s', dust)
        return change, dust

    def make_tx(self, coins: List[XTxInput], outputs: List[XTxOutput],
            change_outs: List[XTxOutput], fee_estimator: TransactionFeeEstimator,
            dust_threshold: int) -> Transaction:
        '''Select unspent coins to spend to pay outputs.  If the change is
        greater than dust_threshold (after adding the change output to
        the transaction) it is kept, otherwise none is sent and it is
        added to the transaction fee.'''
        assert len(change_outs) >= 1

        # Deterministic randomness from coins
        self.p = PRNG(b''.join(sorted(c.prevout_bytes() for c in coins)))

        # Copy the outputs so when adding change we don't modify "outputs".
        tx = Transaction.from_io([], outputs)
        # Size of the transaction with no inputs and no change.
        base_size = tx.estimated_size()
        spent_amount = tx.output_value()

        def sufficient_funds(buckets: List[Bucket]) -> bool:
            '''Given a list of buckets, return True if it has enough value to pay for the
            transaction'''
            total_input_value = sum(bucket.value for bucket in buckets)
            total_size = base_size + cast(TransactionSize, sum(bucket.size for bucket in buckets))
            return total_input_value >= spent_amount + fee_estimator(total_size)

        # Collect the coins into buckets, choose a subset of the buckets
        buckets = self.bucketize_coins(coins)
        buckets = self.choose_buckets(buckets, sufficient_funds, self.create_penalty_function(tx))

        tx.inputs.extend(coin for b in buckets for coin in b.coins)
        tx_size = base_size + cast(TransactionSize, sum(bucket.size for bucket in buckets))

        # This takes a count of change outputs and returns a tx fee;
        change_output_size = change_outs[0].estimated_size()
        fee: ScaledFeeEstimator = lambda count: fee_estimator(tx_size + change_output_size * count)
        change, dust = self.change_outputs(tx, change_outs, fee, dust_threshold)
        tx.outputs.extend(change)

        logger.debug("using %d inputs", len(tx.inputs))
        logger.debug("using buckets: %s", [bucket.desc for bucket in buckets])

        return tx

    def choose_buckets(self, buckets: List[Bucket], sufficient_funds: SufficientFundsCheck,
            penalty_func: BucketPenaltyFunction) -> List[Bucket]:
        raise NotImplementedError('To be subclassed')


class CoinChooserRandom(CoinChooserBase):

    def create_bucket_groupings(self, buckets: List[Bucket],
            sufficient_funds_check: SufficientFundsCheck) -> List[List[Bucket]]:
        '''Returns a list of bucket sets.'''
        valid_bucket_combinations: Set[Sequence[int]] = set()

        # Add all singletons
        for n, bucket in enumerate(buckets):
            if sufficient_funds_check([bucket]):
                valid_bucket_combinations.add((n, ))

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
                if sufficient_funds_check(bkts):
                    valid_bucket_combinations.add(tuple(sorted(permutation[:count + 1])))
                    break
            else:
                raise NotEnoughFunds()

        valid_bucket_groupings = [ [ buckets[n] for n in c ] for c in valid_bucket_combinations ]
        return [ strip_unneeded_coins(c, sufficient_funds_check) for c in valid_bucket_groupings ]

    def choose_buckets(self, buckets: List[Bucket], sufficient_funds: SufficientFundsCheck,
            penalty_func: BucketPenaltyFunction) -> List[Bucket]:
        candidate_groupings = self.create_bucket_groupings(buckets, sufficient_funds)
        penalties = [penalty_func(grouping) for grouping in candidate_groupings]
        winner = candidate_groupings[penalties.index(min(penalties))]
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

    def create_penalty_function(self, tx: Transaction) -> BucketPenaltyFunction:
        out_values = [output.value for output in tx.outputs]
        max_change = max(out_values) * 1.5
        spent_amount = sum(out_values)

        def penalty(buckets: List[Bucket]) -> float:
            badness: float = len(buckets) - 1
            total_input = sum(bucket.value for bucket in buckets)
            change = float(total_input - spent_amount)
            # Penalize change not roughly in output range
            if change > max_change:
                badness += (change - max_change) / (max_change + 10000)
                # Penalize large change; 5 BSV excess ~= using 1 more input
                badness += change / (COIN * 5)
            return badness

        return penalty
