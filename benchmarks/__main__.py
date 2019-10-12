# -*- coding: utf-8 -*-
#!/usr/bin/env python3

"""
Script for benchmarking *pymerkle*
"""

import os
import sys
import argparse
from pymerkle.hashing import HashMachine
from pymerkle.tree.nodes import Node, Leaf
from pymerkle.tree import MerkleTree
from pymerkle.validations import validateProof

write = sys.stdout.write

# Size

from numbers import Number
from collections import Set, Mapping, deque

zero_depth_bases = (str, bytes, Number, range, bytearray)
iteritems = 'items'

def get_size(obj_0):
    """
    Recursively iterate to sum size of object and members

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
            pass # bypass remaining control flow and return
        elif isinstance(obj, (tuple, list, Set, deque)):
            size += sum(inner(_) for _ in obj)
        elif isinstance(obj, Mapping) or hasattr(obj, iteritems):
            size += sum(inner(k) + inner(v) for k, v in getattr(obj, iteritems)())
        # Check for custom object instances - may subclass above too
        if hasattr(obj, '__dict__'):
            size += inner(vars(obj))
        if hasattr(obj, '__slots__'): # can have __slots__ with __dict__
            size += sum(inner(getattr(obj, s))
                for s in obj.__slots__ if hasattr(obj, s))
        return size
    return inner(obj_0)


# Time

from datetime import datetime
now = datetime.now
time_elapsed = lambda start: (now() - start).total_seconds()


# Stats

from decimal import Decimal, ROUND_HALF_UP
from functools import reduce

def quantize(float, precision):
    return Decimal(float).quantize(precision, rounding=ROUND_HALF_UP)

def mean_value(num_lst, precision, with_stdev=False):
    num_lst = [quantize(_, precision) for _ in num_lst]
    length = quantize(num_lst.__len__(), precision)
    mean  = quantize(sum(num_lst)/length, precision)
    if not with_stdev:
        return mean
    else:
        stdev = quantize(reduce(lambda s, k: s + (k - mean) ** 2, num_lst)/(length - 1), precision)
        return mean, stdev

def show_stats(message, mean, stdev, total=None, min=None, max=None):
    write('\n')
    write('\n%s' % message)
    write('\n')
    write('\nMean  : %s' % mean)
    write('\nStDev : %s' % stdev)
    if min is not None:
        write('\nMax   : %s' % max)
    if max is not None:
        write('\nMin   : %s' % min)
    if total is not None:
        write('\nTotal : %s' % total)


# Benchmarks

def attribute_access_benchmark():
    from timeit import repeat

    def access_digest_func(node):
        def access_attribute(): node.digest
        return access_attribute

    def access_left_parent_func(node):
        def access_attribute(): node.left
        return access_attribute

    def access_right_parent_func(node):
        def access_attribute(): node.right
        return access_attribute

    def access_child_func(node):
        def access_attribute(): node.child
        return access_attribute

    left  = Leaf(hash_func=HASH, encoding=ENCODING, record='first record...')
    right = Leaf(hash_func=HASH, encoding=ENCODING, record='second record...')
    node  = Node(hash_func=HASH, encoding=ENCODING, left=left, right=right)


    write('\n\n-------------------------- Nodes\' attributes access --------------------------')
    write('\n')
    write('\nConfiguration')
    write('\n')
    write('\nNumber of rounds     : %d' % ROUNDS)
    write('\nNumber of iterations : %d' % ITERATIONS)

    # Digest access
    access_digest_measurements = repeat(
        access_digest_func(left),
        repeat=ITERATIONS,
        number=ROUNDS
    )
    mean, stdev = mean_value(access_digest_measurements,
        PRECISION_1, with_stdev=True)
    show_stats('Time needed to access digest (sec)', mean, stdev)

    # Left parent access
    access_left_parent_measurements = repeat(
        access_left_parent_func(node),
        repeat=ITERATIONS,
        number=ROUNDS
    )
    mean, stdev = mean_value(access_left_parent_measurements,
        PRECISION_1, with_stdev=True)
    show_stats('Time needed to access left parent (sec)', mean, stdev)

    # Right parent access
    access_right_parent_measurements = repeat(
        access_right_parent_func(node),
        repeat=ITERATIONS,
        number=ROUNDS
    )
    mean, stdev = mean_value(access_right_parent_measurements,
        PRECISION_1, with_stdev=True)
    show_stats('Time needed to access right parent (sec)', mean, stdev)

    # Child access
    access_child_measurements = repeat(
        access_child_func(right),
        repeat=ITERATIONS,
        number=ROUNDS
    )
    mean, stdev = mean_value(access_child_measurements,
        PRECISION_1, with_stdev=True)
    show_stats('Time needed to access child (sec)', mean, stdev)


def tree_generation_benchmark():
    write('\n\n------------------- Tree generation and size measuremenets -------------------')
    write('\n')

    args = ['%d-th record' % _ for _ in range(LENGTH)]

    global TREE
    start = now()
    TREE = MerkleTree(*args, hash_type=HASH_TYPE, encoding=ENCODING)
    time_needed = time_elapsed(start)

    write('\nNumber of leaves      : %d\n' % TREE.length)
    write('\nGeneration time (sec) : %s' % time_needed)
    write('\nSize of tree (bytes)  : %d' % get_size(TREE))


def sizes_benchmark():

    # Leaves measurement
    MAX    = None
    MIN    = None
    TOTAL  = 0.0
    sizes = []
    for leaf in TREE.leaves:
        current_size = get_size(leaf)
        if MAX is None:
            MAX = current_size
            MIN = current_size
        else:
            MAX = max(current_size, MAX)
            MIN = min(current_size, MIN)
        TOTAL += current_size
        sizes.append(current_size)
    mean, stdev = mean_value(sizes, precision=Decimal('1'), with_stdev=True)
    show_stats(message='Leaves\' size (bytes)',
        total=TOTAL, min=MIN, max=MAX, mean=mean, stdev=stdev)

    # Internal nodes measurement
    MAX    = None
    MIN    = None
    TOTAL  = 0.0
    sizes = []
    for node in TREE.nodes - set(TREE.leaves):
        current_size = get_size(node)
        if MAX is None:
            MAX = current_size
            MIN = current_size
        else:
            MAX = max(current_size, MAX)
            MIN = min(current_size, MIN)
        TOTAL += current_size
        sizes.append(current_size)
    mean, stdev = mean_value(sizes, precision=Decimal('1'), with_stdev=True)
    show_stats(message='Internal nodes\' size (bytes)',
        total=TOTAL, min=MIN, max=MAX, mean=mean, stdev=stdev)



def encryption_benchmark():
    write('\n\n-------------------------- Encryption measuremenets ---------------------------\n')

    # Massive encryption measurement
    write('\n')
    write('Massive encryption measurement')
    write('\n')

    start = now()
    for _ in range(LENGTH, LENGTH + ADDITIONAL):
        TREE.encryptRecord('%d-th record' % _)
    time_needed = time_elapsed(start)

    write('\nNew size of tree (bytes)          : %d' % get_size(TREE))
    write('\nTotal number of leaves            : %s' % TREE.length)
    write('\nNumber of newly-appended leaves   : %d' % ADDITIONAL)
    write('\nTotal time needed to append (sec) : %d' % time_needed)

    # Single encryption measurements
    write('\n\nEncrypting %d further records...' % ADDITIONAL)
    MAX   = None
    MIN   = None
    TOTAL = 0.0
    elapsed = []
    start = now()
    for _ in range(TREE.length, TREE.length + ADDITIONAL):
        cycle = now()
        TREE.update(record='%d-th record' % _)
        _elapsed = time_elapsed(cycle)
        if MAX is None:
            MAX = _elapsed
            MIN = _elapsed
        else:
            MAX = max(_elapsed, MAX)
            MIN = min(_elapsed, MIN)
        TOTAL += _elapsed
        elapsed.append(_elapsed)
    mean, stdev = mean_value(elapsed, PRECISION_2, with_stdev=True)
    show_stats(message='Single encryption measurements',
        total=quantize(TOTAL, PRECISION_2), min=MIN, max=MAX, mean=mean, stdev=stdev)


def audit_proofs_benchmark():
    write('\n\n----------------------- Proof generation measuremenets ------------------------')
    write('\n\n')
    write('Generating audit-proofs -be patient...\n')
    global PROOFS
    START = now()
    MAX   = None
    MIN   = None
    TOTAL = 0.0
    elapsed = []
    for leaf in TREE.leaves:
        cycle = now()
        proof = TREE.auditProof(leaf.digest)
        _elapsed = time_elapsed(cycle)
        if MAX is None:
            MAX = _elapsed
            MIN = _elapsed
        else:
            MAX = max(_elapsed, MAX)
            MIN = min(_elapsed, MIN)
        PROOFS.append(proof)
        TOTAL += _elapsed
        elapsed.append(_elapsed)
    mean, stdev = mean_value(elapsed, PRECISION_2, with_stdev=True)
    show_stats(
        message='Audit-proof generation (sec)', total=quantize(TOTAL, PRECISION_2),
        min=MIN, max=MAX, mean=mean, stdev=stdev)


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
    START = now()
    MAX   = None
    MIN   = None
    TOTAL = 0.0
    elapsed = []
    for _ in range(TREE.length):
        subhash   = states[_][0]
        sublength = states[_][1]
        cycle = now()
        proof = TREE.consistencyProof(subhash=subhash, sublength=sublength)
        _elapsed = time_elapsed(cycle)
        if MAX is None:
            MIN = MAX = _elapsed
        else:
            MAX = max(_elapsed, MAX)
            MIN = min(_elapsed, MIN)
        PROOFS.append(proof)
        TOTAL += _elapsed
        elapsed.append(_elapsed)
    mean, stdev = mean_value(elapsed, PRECISION_2, with_stdev=True)
    show_stats(
        message='\nConsistency-proof generation (sec)',
        total=quantize(TOTAL, PRECISION_2), min=MIN, max=MAX, mean=mean, stdev=stdev
    )


def proof_validations_benchmark():
    write('\n\n------------------------ Proof validation measuremenets ------------------------\n')
    write('\nSize of sample : %d' % len(PROOFS))

    START = now()
    MAX   = None
    MIN   = None
    TOTAL = 0.0
    elapsed = []
    for proof in PROOFS:
        cycle   = now()
        validateProof(target=TREE.rootHash, proof=proof)
        _elapsed = time_elapsed(cycle)
        if MAX is None:
            MAX = _elapsed
            MIN = _elapsed
        else:
            MAX = max(_elapsed, MAX)
            MIN = min(_elapsed, MIN)
        TOTAL += _elapsed
        elapsed.append(_elapsed)
    mean, stdev = mean_value(elapsed, PRECISION_2, with_stdev=True)
    show_stats(message='Proof validation (sec)',
        total=quantize(TOTAL, PRECISION_2), min=MIN, max=MAX, mean=mean, stdev=stdev)


# main

HASH_TYPE    = None
ENCODING     = None
HASH         = None
LENGTH       = None
ADDITIONAL   = None
ITERATIONS   = None
ROUNDS       = None

TREE         = None
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
    usage = 'python %s [--hashtype] [--encoding] [--length] [--additional] [--iterations] [--rounds]' % prog

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

    parsed_args = parser.parse_args()

    HASH_TYPE  = parsed_args.hashtype
    ENCODING   = parsed_args.encoding
    HASH       = HashMachine(hash_type=HASH_TYPE, encoding=ENCODING).hash
    LENGTH     = parsed_args.length
    ADDITIONAL = parsed_args.additional
    ITERATIONS = parsed_args.iterations
    ROUNDS     = parsed_args.rounds

    write('============================= pymerkle benchmarks ============================')
    write('\nConfiguration')
    write('\n')
    write('\nHash type : %s' % HASH_TYPE)
    write('\nEncoding  : %s' % ENCODING)

    attribute_access_benchmark()
    tree_generation_benchmark()
    sizes_benchmark()
    encryption_benchmark()
    audit_proofs_benchmark()
    consistency_proofs_benchmark()
    proof_validations_benchmark()

    write('\n')
    sys.exit(0)

if __name__ == "__main__":
    main()
