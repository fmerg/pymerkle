# -*- coding: utf-8 -*-
#!/usr/bin/env python3

"""Script for benchmarking *pymerkle*
"""

import os
import sys
import argparse
import inspect

# Make pymerkle importable

current_dir = os.path.dirname(
    os.path.abspath(
        inspect.getfile(
            inspect.currentframe())))
sys.path.insert(0, os.path.dirname(current_dir))

from pymerkle.nodes import Node, Leaf
from pymerkle.hashing import hash_machine
from pymerkle import MerkleTree
from pymerkle.validations import validateProof


# ---------------------------------- Helpers ----------------------------------



from numbers import Number
from collections import Set, Mapping, deque

zero_depth_bases = (str, bytes, Number, range, bytearray)
iteritems = 'items'

def _size(obj_0):
    """Recursively iterate to sum size of object and members

    By Aaron Hall
    https://stackoverflow.com/questions/449560/how-do-i-determine-the-size-of-an-object-in-python
    """
    _seen_ids = set()

    def inner(obj):
        obj_id = id(obj)

        if obj_id in _seen_ids:
            return 0

        _seen_ids.add(obj_id)

        size = sys.getsizeof(obj)

        if isinstance(obj, zero_depth_bases):
            pass                                                                # bypass remaining control flow and return
        elif isinstance(obj, (tuple, list, Set, deque)):
            size += sum(inner(_) for _ in obj)
        elif isinstance(obj, Mapping) or hasattr(obj, iteritems):
            size += sum(inner(k) + inner(v) for k, v in getattr(obj, iteritems)())

        # Check for custom object instances - may subclass above too

        if hasattr(obj, '__dict__'):
            size += inner(vars(obj))

        if hasattr(obj, '__slots__'):                                           # can have __slots__ with __dict__
            size += sum(
                inner(getattr(obj, s)) for s in obj.__slots__ if hasattr(obj, s)
            )
        return size

    return inner(obj_0)


from decimal import Decimal, ROUND_HALF_UP
from functools import reduce

def _quantize(_float, precision):
    return Decimal(_float).quantize(precision, rounding=ROUND_HALF_UP)

def _mean_value(_list, precision, with_stdev=False):
    """Accepts an iterable of numbers, returns a string
    """

    _list = [_quantize(_, precision) for _ in _list]

    sum    = reduce(lambda x, y: x + y, _list)
    length = _quantize(_list.__len__(), precision)

    if not with_stdev:

        return _quantize(sum/length, precision)

    else:

        mean  = _quantize(sum/length, precision)

        stdev = _quantize(reduce(lambda s, k: s + (k - mean) ** 2, _list)/(length - 1), precision)

        return mean, stdev


from datetime import datetime

_time_elapsed = lambda start: (datetime.now() - start).total_seconds()


def _show_stats(message, mean, stdev, total=None, min=None, max=None):
    sys.stdout.write('\n')
    sys.stdout.write('\n%s' % message)
    sys.stdout.write('\n')
    if total is not None:
        sys.stdout.write('\nTotal time : %s' % total)
    if min is not None:
        sys.stdout.write('\nMax time   : %s' % max)
    if max is not None:
        sys.stdout.write('\nMin time   : %s' % min)
    sys.stdout.write('\nMean       : %s' % mean)
    sys.stdout.write('\nStDev      : %s' % stdev)


# --------------------------------- Benchmarks ---------------------------------


HASH_TYPE    = 'sha256'
ENCODING     = 'utf-8'

MACHINE      = hash_machine(hash_type=HASH_TYPE, encoding=ENCODING)
ENCODING     = MACHINE.ENCODING
HASH         = MACHINE.hash

TREE         = MerkleTree(hash_type=HASH_TYPE, encoding=ENCODING)
LENGTH       = 10 ** 3 # 4 # 5
ADDITIONAL   = 10 ** 3 # 4 # 5 # 10 ** 6

ITERATIONS   = 10 ** 3
ROUNDS       = 20 # 10 ** 5

PROOFS       = []



PRECISION_1    = 12
PRECISION_2    = 6

precision_1 = Decimal('.%s1' % ('0' * (PRECISION_1 - 1)))
precision_2 = Decimal('.%s1' % ('0' * (PRECISION_2 - 1)))


import timeit


def nodes_benchmark():

    def access_digest_func(_node):
        def access_attribute(): _node.digest
        return access_attribute

    def access_left_parent_func(_node):
        def access_attribute(): _node.left
        return access_attribute

    def access_right_parent_func(_node):
        def access_attribute(): _node.right
        return access_attribute

    def access_child_func(_node):
        def access_attribute(): _node.child
        return access_attribute

    left  = Leaf(hashfunc=HASH, encoding=ENCODING, record='first record...')
    right = Leaf(hashfunc=HASH, encoding=ENCODING, record='second record...')
    node  = Node(hashfunc=HASH, encoding=ENCODING, left=left, right=right)

    # Size measurement

    sys.stdout.write('\nSize of leaf with encoding %s and hash type %s (bytes): %d' % (ENCODING, HASH_TYPE, _size(left)))
    sys.stdout.write('\nSize of internal node with encoding %s and hash type %s (bytes): %d' % (ENCODING, HASH_TYPE, _size(left)))

    # Digest access

    access_digest_measurements = timeit.repeat(
        access_digest_func(left),
        repeat=ITERATIONS,
        number=ROUNDS
    )

    mean, stdev = _mean_value(access_digest_measurements, precision=precision_1, with_stdev=True)
    _show_stats('Time needed to access digest (secs)', mean, stdev)
    # sys.stdout.write('\n')
    # sys.stdout.write('\nMean time needed to access the digest (secs): %s' % (mean.__str__()))
    # sys.stdout.write('\nStDev: %s' % (stdev.__str__()))

    # Left parent access

    access_left_parent_measurements = timeit.repeat(
        access_left_parent_func(node),
        repeat=ITERATIONS,
        number=ROUNDS
    )

    mean, stdev = _mean_value(access_left_parent_measurements, precision=precision_1, with_stdev=True)
    _show_stats('Time needed to access left parent (secs)', mean, stdev)
    # sys.stdout.write('\n')
    # sys.stdout.write('\nMean time needed to access left parent (secs): %s' % (mean.__str__()))
    # sys.stdout.write('\nStDev: %s' % (stdev.__str__()))

    # Right parent access

    access_right_parent_measurements = timeit.repeat(
        access_right_parent_func(node),
        repeat=ITERATIONS,
        number=ROUNDS
    )

    mean, stdev = _mean_value(access_right_parent_measurements, precision=precision_1, with_stdev=True)
    _show_stats('Time needed to access right parent (secs)', mean, stdev)
    # sys.stdout.write('\n')
    # sys.stdout.write('\nMean time needed to access the let parent (secs): %s' % (mean.__str__()))
    # sys.stdout.write('\nStDev: %s' % (stdev.__str__()))

    # Child access

    access_child_measurements = timeit.repeat(
        access_child_func(right),
        repeat=ITERATIONS,
        number=ROUNDS
    )

    mean, stdev = _mean_value(access_child_measurements, precision=precision_1, with_stdev=True)
    _show_stats('Time needed to access child (secs)', mean, stdev)
    # sys.stdout.write('\n')
    # sys.stdout.write('\nMean time needed to access the child (secs): %s' % (mean.__str__()))
    # sys.stdout.write('\nStDev: %s' % (stdev.__str__()))


def tree_benchmark():
    global TREE

    sys.stdout.write('\n')
    sys.stdout.write('\nTree size with 0 nodes (bytes): %d' % _size(TREE))
    START = datetime.now()

    TREE = MerkleTree(*['%d-th record' % _ for _ in range(LENGTH)], hash_type=HASH_TYPE, encoding=ENCODING)

    time_needed = _time_elapsed(START)

    sys.stdout.write('\n')
    sys.stdout.write('\nTime needed to generate a Merkle-tree with %d leaves (secs): %s' % (LENGTH, time_needed))
    sys.stdout.write('\nSize of tree with %d leaves (bytes): %d' % (TREE.length, _size(TREE)))


    START = datetime.now()

    for _ in range(LENGTH, LENGTH + ADDITIONAL):
        TREE.encryptRecord('%d-th record' % _)

    time_needed = _time_elapsed(START)

    sys.stdout.write('\n')
    sys.stdout.write('\nTime needed to update the tree with %d leaves (secs): %f' % (ADDITIONAL, time_needed))
    sys.stdout.write('\nSize of tree with %d leaves (bytes): %d' % (TREE.length, _size(TREE)))


    #

    START = datetime.now()
    MAX   = None
    MIN   = None
    TOTAL = 0.0

    elapsed = []

    for _ in range(TREE.length, TREE.length + ADDITIONAL):

        _cycle   = datetime.now()

        TREE.update(record='%d-th record' % _)

        _elapsed = _time_elapsed(_cycle)

        if MAX is None:
            MAX = _elapsed
            MIN = _elapsed
        else:
            MAX = max(_elapsed, MAX)
            MIN = min(_elapsed, MIN)

        TOTAL += _elapsed
        elapsed.append(_elapsed)

    mean, stdev = _mean_value(elapsed, precision_2, with_stdev=True)
    _show_stats(message='Tree update', total=_quantize(TOTAL, precision_2), min=MIN, max=MAX, mean=mean, stdev=stdev)



def audit_proofs_benchmark():

    global PROOFS

    START = datetime.now()
    MAX   = None
    MIN   = None
    TOTAL = 0.0

    elapsed = []

    for _ in range(TREE.length):

        _cycle   = datetime.now()

        _proof = TREE.auditProof(arg='%d-th record' % _)

        _elapsed = _time_elapsed(_cycle)

        # print(_proof)
        # print(_)

        if MAX is None:
            MAX = _elapsed
            MIN = _elapsed
        else:
            MAX = max(_elapsed, MAX)
            MIN = min(_elapsed, MIN)

        PROOFS.append(_proof)
        TOTAL += _elapsed
        elapsed.append(_elapsed)

    mean, stdev = _mean_value(elapsed, precision_2, with_stdev=True)
    _show_stats(message='Audit proofs', total=_quantize(TOTAL, precision_2), min=MIN, max=MAX, mean=mean, stdev=stdev)


def consistency_proofs_benchmark():

    # Generate states

    global TREE
    TREE = MerkleTree('0-th record', encoding=ENCODING, hash_type=HASH_TYPE)

    STATES = []
    for _ in range(1, LENGTH + 3 * ADDITIONAL):#):

        STATES.append((TREE.rootHash, TREE.length))
        TREE.encryptRecord(bytes('%d-th record' % _, encoding=ENCODING))

    STATES.append((TREE.rootHash, TREE.length))

    # Generate proofs

    global PROOFS

    sys.stdout.write('\nConsistency proofs')

    START = datetime.now()
    MAX   = None
    MIN   = None
    TOTAL = 0.0

    elapsed = []

    for _ in range(TREE.length):

        # print(_)

        _oldhash   = STATES[_][0]
        _sublength = STATES[_][1]

        _cycle   = datetime.now()

        _proof = TREE.consistencyProof(oldhash=_oldhash, sublength=_sublength)

        _elapsed = _time_elapsed(_cycle)

        # print(_proof)
        # print(_)

        if MAX is None:
            MIN = MAX = _elapsed
        else:
            MAX = max(_elapsed, MAX)
            MIN = min(_elapsed, MIN)

        PROOFS.append(_proof)
        TOTAL += _elapsed
        elapsed.append(_elapsed)

    mean, stdev = _mean_value(elapsed, precision_2, with_stdev=True)
    _show_stats(message='Consistency proofs' , total=_quantize(TOTAL, precision_2), min=MIN, max=MAX, mean=mean, stdev=stdev)



def proof_validations_benchmark():

    global PROOFS

    START = datetime.now()
    MAX   = None
    MIN   = None
    TOTAL = 0.0

    elapsed = []

    for _proof in PROOFS:

        _cycle   = datetime.now()

        validateProof(target=TREE.rootHash, proof=_proof)

        _elapsed = _time_elapsed(_cycle)


        if MAX is None:
            MAX = _elapsed
            MIN = _elapsed
        else:
            MAX = max(_elapsed, MAX)
            MIN = min(_elapsed, MIN)

        TOTAL += _elapsed
        elapsed.append(_elapsed)

    mean, stdev = _mean_value(elapsed, precision_2, with_stdev=True)
    _show_stats(message='Proof validations', total=_quantize(TOTAL, precision_2), min=MIN, max=MAX, mean=mean, stdev=stdev)

# ------------------------------------ main ------------------------------------

def main():

    prog = sys.argv[0]
    usage = 'python3 ... %s' % prog

    parser = argparse.ArgumentParser(
        prog=prog,
        usage=usage,
        description=__doc__,
        epilog='\n'
    )

    parser.add_argument(
        '--hashtype',
        help='Hashing algorithm used by the Merkle-tree',
        dest='hashtype',
        default='sha256'
    )

    parser.add_argument(
        '-e', '--encoding',
        help='Encoding used by the Merkle-tree before hashing',
        dest='encoding',
        default='utf_8'
    )

    parser.add_argument(
        '-s', '--security',
        help='Security mode of the Merkle-tree',
        dest='security',
        default=True
    )

    parser.add_argument(
        '-c', '--contentpath',
        help='Relative path to a file whose content will be encrypted',
        dest='contentpath',
        default='../pymerkle/tests/logs/short_APACHE_log'
    )

    parser.add_argument(
        '--logfile',
        help='Relative path to a log-file under encryption',
        dest='logfile',
        default='../pymerkle/tests/logs/short_APACHE_log'
    )

    parser.add_argument(
        '-o', '--objectfile',
        help='Relative path to a .json file',
        dest='objectfile',
        default='../pymerkle/tests/objects/sample.json'
    )

    nodes_benchmark()
    tree_benchmark()
    audit_proofs_benchmark()
    consistency_proofs_benchmark()
    proof_validations_benchmark()

    sys.stdout.write('\n')
    sys.exit(0)

if __name__ == "__main__":
    main()
