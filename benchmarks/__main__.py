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

# Size measurement

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


# Time measurement

from datetime import datetime

_time_elapsed = lambda start: (datetime.now() - start).total_seconds()


# Statistics

from decimal import Decimal, ROUND_HALF_UP
from functools import reduce

_quantize = lambda _float, precision: Decimal(_float).quantize(precision, rounding=ROUND_HALF_UP)

def _mean_value(_list, precision, with_stdev=False):

    _list = [_quantize(_, precision) for _ in _list]

    sum    = reduce(lambda x, y: x + y, _list)
    length = _quantize(_list.__len__(), precision)

    if not with_stdev:

        return _quantize(sum/length, precision)

    else:

        mean  = _quantize(sum/length, precision)

        stdev = _quantize(reduce(lambda s, k: s + (k - mean) ** 2, _list)/(length - 1), precision)

        return mean, stdev


# Stats display

def show_stats(message, mean, stdev, total=None, min=None, max=None):
    sys.stdout.write('\n')
    sys.stdout.write('\n%s' % message)
    sys.stdout.write('\n')
    sys.stdout.write('\nMean  : %s' % mean)
    sys.stdout.write('\nStDev : %s' % stdev)
    if min is not None:
        sys.stdout.write('\nMax   : %s' % max)
    if max is not None:
        sys.stdout.write('\nMin   : %s' % min)
    if total is not None:
        sys.stdout.write('\nTotal : %s' % total)


# --------------------------------- Benchmarks ---------------------------------


import timeit

def attribute_access_benchmark():

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


    sys.stdout.write('\n\n\n----------------------------------------- Nodes\' attributes access -----------------------------------------')
    sys.stdout.write('\n')
    sys.stdout.write('\nConfiguration')
    sys.stdout.write('\n')
    sys.stdout.write('\nNumber of rounds     : %d' % ROUNDS)
    sys.stdout.write('\nNumber of iterations : %d' % ITERATIONS)


    # Digest access

    access_digest_measurements = timeit.repeat(
        access_digest_func(left),
        repeat=ITERATIONS,
        number=ROUNDS
    )


    mean, stdev = _mean_value(access_digest_measurements, PRECISION_1, with_stdev=True)

    show_stats('\nTime needed to access digest (sec)', mean, stdev)


    # Left parent access

    access_left_parent_measurements = timeit.repeat(
        access_left_parent_func(node),
        repeat=ITERATIONS,
        number=ROUNDS
    )

    mean, stdev = _mean_value(access_left_parent_measurements, PRECISION_1, with_stdev=True)

    show_stats('\nTime needed to access left parent (sec)', mean, stdev)


    # Right parent access

    access_right_parent_measurements = timeit.repeat(
        access_right_parent_func(node),
        repeat=ITERATIONS,
        number=ROUNDS
    )

    mean, stdev = _mean_value(access_right_parent_measurements, PRECISION_1, with_stdev=True)

    show_stats('\nTime needed to access right parent (sec)', mean, stdev)


    # Child access

    access_child_measurements = timeit.repeat(
        access_child_func(right),
        repeat=ITERATIONS,
        number=ROUNDS
    )

    mean, stdev = _mean_value(access_child_measurements, PRECISION_1, with_stdev=True)

    show_stats('\nTime needed to access child (sec)', mean, stdev)



def tree_generation_benchmark():

    sys.stdout.write('\n\n\n---------------------------------- Tree generation and size measuremenets ----------------------------------')
    sys.stdout.write('\n')

    global TREE

    start = datetime.now()

    TREE = MerkleTree(*['%d-th record' % _ for _ in range(LENGTH)], hash_type=HASH_TYPE, encoding=ENCODING)

    time_needed = _time_elapsed(start)

    sys.stdout.write('\nNumber of leaves      : %d\n' % TREE.length)
    sys.stdout.write('\nGeneration time (sec) : %s' % time_needed)
    sys.stdout.write('\nSize of tree (bytes)  : %d' % _size(TREE))


def sizes_benchmark():

    # Leaves measurement

    MAX    = None
    MIN    = None
    TOTAL  = 0.0

    _sizes = []

    for _leaf in TREE.leaves:

        _current_size = _size(_leaf)

        if MAX is None:
            MAX = _current_size
            MIN = _current_size
        else:
            MAX = max(_current_size, MAX)
            MIN = min(_current_size, MIN)

        TOTAL += _current_size
        _sizes.append(_current_size)


    mean, stdev = _mean_value(_sizes, precision=Decimal('1'), with_stdev=True)

    show_stats(message='\nLeaves\' size (bytes)', total=TOTAL, min=MIN, max=MAX, mean=mean, stdev=stdev)


    # Internal nodes measurement

    MAX    = None
    MIN    = None
    TOTAL  = 0.0

    _sizes = []

    for _node in TREE.nodes - set(TREE.leaves):

        _current_size = _size(_node)

        if MAX is None:
            MAX = _current_size
            MIN = _current_size
        else:
            MAX = max(_current_size, MAX)
            MIN = min(_current_size, MIN)

        TOTAL += _current_size
        _sizes.append(_current_size)


    mean, stdev = _mean_value(_sizes, precision=Decimal('1'), with_stdev=True)

    show_stats(message='\nInternal nodes\' size (bytes)', total=TOTAL, min=MIN, max=MAX, mean=mean, stdev=stdev)



def encryption_benchmark():

    sys.stdout.write('\n\n\n--------------------------------------- Encryption measuremenets ----------------------------------------\n')

    # Massive encryption measurement

    sys.stdout.write('\n')
    sys.stdout.write('Massive encryption measurement')
    sys.stdout.write('\n')

    start = datetime.now()

    for _ in range(LENGTH, LENGTH + ADDITIONAL):
        TREE.encryptRecord('%d-th record' % _)

    time_needed = _time_elapsed(start)

    sys.stdout.write('\nNew size of tree (bytes)          : %d' % _size(TREE))
    sys.stdout.write('\nTotal number of leaves            : %s' % TREE.length)
    sys.stdout.write('\nNumber of newly-appended leaves   : %d' % ADDITIONAL)
    sys.stdout.write('\nTotal time needed to append (sec) : %d' % time_needed)


    # Single encryption measurements

    sys.stdout.write('\n\n\nEncrypting %d further records...\n' % ADDITIONAL)

    MAX   = None
    MIN   = None
    TOTAL = 0.0

    elapsed = []
    start = datetime.now()

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


    mean, stdev = _mean_value(elapsed, PRECISION_2, with_stdev=True)

    show_stats(message='Single encryption measurements', total=_quantize(TOTAL, PRECISION_2), min=MIN, max=MAX, mean=mean, stdev=stdev)



def audit_proofs_benchmark():

    sys.stdout.write('\n\n\n------------------------------------ Proof generation measuremenets -------------------------------------\n')

    global PROOFS

    START = datetime.now()
    MAX   = None
    MIN   = None
    TOTAL = 0.0

    elapsed = []

    for _ in range(TREE.length):

        _cycle   = datetime.now()

        _proof = TREE.auditProof(arg=_)

        _elapsed = _time_elapsed(_cycle)

        if MAX is None:
            MAX = _elapsed
            MIN = _elapsed
        else:
            MAX = max(_elapsed, MAX)
            MIN = min(_elapsed, MIN)

        PROOFS.append(_proof)
        TOTAL += _elapsed
        elapsed.append(_elapsed)


    mean, stdev = _mean_value(elapsed, PRECISION_2, with_stdev=True)

    show_stats(
        message='Audit-proof generation %s(sec)' % ('with index provided ' if RECORD else ''),
        total=_quantize(TOTAL, PRECISION_2), min=MIN, max=MAX, mean=mean, stdev=stdev
    )

    if RECORD:

        sys.stdout.write('\n\n\n')
        sys.stdout.write('Generating audit-proofs upon records -be patient...\n')

        START = datetime.now()
        MAX   = None
        MIN   = None
        TOTAL = 0.0

        elapsed = []

        for _ in range(TREE.length):

            _cycle   = datetime.now()

            _proof = TREE.auditProof(arg='%d-th record' % _)

            _elapsed = _time_elapsed(_cycle)

            if MAX is None:
                MAX = _elapsed
                MIN = _elapsed
            else:
                MAX = max(_elapsed, MAX)
                MIN = min(_elapsed, MIN)

            PROOFS.append(_proof)
            TOTAL += _elapsed
            elapsed.append(_elapsed)


        mean, stdev = _mean_value(elapsed, PRECISION_2, with_stdev=True)

        show_stats(
            message='Audit-proof generation with record (sec)',
            total=_quantize(TOTAL, PRECISION_2), min=MIN, max=MAX, mean=mean, stdev=stdev
        )



def consistency_proofs_benchmark():

    # Generate states

    TREE = MerkleTree('0-th record', encoding=ENCODING, hash_type=HASH_TYPE)

    states = []

    for _ in range(1, LENGTH + 3 * ADDITIONAL):

        states.append((TREE.rootHash, TREE.length))
        TREE.encryptRecord(bytes('%d-th record' % _, encoding=ENCODING))

    states.append((TREE.rootHash, TREE.length))

    # Generate proofs

    global PROOFS

    START = datetime.now()
    MAX   = None
    MIN   = None
    TOTAL = 0.0

    elapsed = []

    for _ in range(TREE.length):

        _oldhash   = states[_][0]
        _sublength = states[_][1]

        _cycle   = datetime.now()

        _proof = TREE.consistencyProof(oldhash=_oldhash, sublength=_sublength)

        _elapsed = _time_elapsed(_cycle)

        if MAX is None:
            MIN = MAX = _elapsed
        else:
            MAX = max(_elapsed, MAX)
            MIN = min(_elapsed, MIN)

        PROOFS.append(_proof)
        TOTAL += _elapsed
        elapsed.append(_elapsed)


    mean, stdev = _mean_value(elapsed, PRECISION_2, with_stdev=True)

    show_stats(
        message='\nConsistency-proof generation (sec)',
        total=_quantize(TOTAL, PRECISION_2), min=MIN, max=MAX, mean=mean, stdev=stdev
    )



def proof_validations_benchmark():

    sys.stdout.write('\n\n\n------------------------------------- Proof validation measuremenets -------------------------------------\n')
    sys.stdout.write('\nSize of sample : %d' % len(PROOFS))

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


    mean, stdev = _mean_value(elapsed, PRECISION_2, with_stdev=True)

    show_stats(message='\nProof validation (sec)', total=_quantize(TOTAL, PRECISION_2), min=MIN, max=MAX, mean=mean, stdev=stdev)


# ------------------------------------ main ------------------------------------

HASH_TYPE    = None
ENCODING     = None
HASH         = None
LENGTH       = None
ADDITIONAL   = None
ITERATIONS   = None
ROUNDS       = None

TREE         = None
RECORD       = False
PROOFS       = []

PRECISION_1 = Decimal('.%s1' % ('0' * 11))  # 0.000000000001, used for attribute access measurements
PRECISION_2 = Decimal('.%s1' % ('0' * 5))   # 0.000001, used for the rest measurements (except for mem space)

def main():

    global HASH_TYPE
    global ENCODING
    global HASH
    global LENGTH
    global ADDITIONAL
    global ITERATIONS
    global ROUNDS
    global RECORD

    prog = sys.argv[0]
    usage = 'python %s [--hashtype] [--encoding] [--length] [--additional] [--iterations] [--rounds] [-r]' % prog

    parser = argparse.ArgumentParser(
        prog=prog,
        usage=usage,
        description=__doc__,
        epilog='\n'
    )

    parser.add_argument(
        '--hashtype',
        type=str,
        help='Hash algorithm to be used by the Merkle-tree',
        default='sha256'
    )

    parser.add_argument(
        '--encoding',
        type=str,
        help='Encoding to be used by the Merkle-tree',
        default='utf_8'
    )

    parser.add_argument(
        '--length',
        type=int,
        help='Initial number of leaves',
        default=7000
    )

    parser.add_argument(
        '--additional',
        type=int,
        help='Additional number of leaves to append (twice)',
        default=2000
    )

    parser.add_argument(
        '--iterations',
        type=int,
        help='Number of iterations when accessing node\'s attributes',
        default=1000
    )

    parser.add_argument(
        '--rounds',
        type=int,
        help='Number of rounds when accessing node\'s attributes',
        default=20
    )

    parser.add_argument(
        '-r',
        action='store_true',
        help="""If provided, audit-proof generation will be also measured with respect to
                records as provided argument (worse case than providing the leaf index)""")

    parsed_args = parser.parse_args()

    HASH_TYPE  = parsed_args.hashtype
    ENCODING   = parsed_args.encoding
    _machine   = hash_machine(hash_type=HASH_TYPE, encoding=ENCODING)
    HASH       = _machine.hash
    LENGTH     = parsed_args.length
    ADDITIONAL = parsed_args.additional
    ITERATIONS = parsed_args.iterations
    ROUNDS     = parsed_args.rounds
    RECORD     = parsed_args.r

    sys.stdout.write('\n\n============================================ pymerkle benchmarks ============================================')
    sys.stdout.write('\n')
    sys.stdout.write('\nConfiguration')
    sys.stdout.write('\n')
    sys.stdout.write('\nHash type : %s' % HASH_TYPE)
    sys.stdout.write('\nEncoding  : %s' % ENCODING)

    attribute_access_benchmark()
    tree_generation_benchmark()
    sizes_benchmark()
    encryption_benchmark()
    audit_proofs_benchmark()
    consistency_proofs_benchmark()
    proof_validations_benchmark()

    sys.stdout.write('\n\n')
    sys.exit(0)

if __name__ == "__main__":
    main()
