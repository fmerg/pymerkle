# -*- coding: utf-8 -*-
#!/usr/bin/env python

import os
import sys
import inspect

# Make pymerkle importable

current_dir = os.path.dirname(
    os.path.abspath(
        inspect.getfile(
            inspect.currentframe()
        )
    )
)
sys.path.insert(0, os.path.dirname(current_dir))

from pymerkle.nodes import Node, Leaf
from pymerkle.hashing import hash_machine
from pymerkle import MerkleTree


# ---------------------------------- Helpers ----------------------------------


from timeit import timeit

def _time_elapsed(start):
    return (datetime.now() - start).total_seconds()


from numbers import Number
from collections import Set, Mapping, deque
from datetime import datetime
import logging

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
            size += sum(inner(i) for i in obj)
        elif isinstance(obj, Mapping) or hasattr(obj, iteritems):
            size += sum(inner(k) + inner(v) for k, v in getattr(obj, iteritems)())

        # Check for custom object instances - may subclass above too

        if hasattr(obj, '__dict__'):
            size += inner(vars(obj))
        if hasattr(obj, '__slots__'):                                           # can have __slots__ with __dict__
            size += sum(inner(getattr(obj, s))
                        for s in obj.__slots__ if hasattr(obj, s))
        return size

    return inner(obj_0)



def _get_logger():
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)

    streamHandler = logging.StreamHandler()
    streamHandler.setLevel(logging.INFO)

    streamFormatter = logging.Formatter('[%(levelname)s] %(message)s')
    streamHandler.setFormatter(streamFormatter)
    logger.addHandler(streamHandler)

    return logger


# --------------------------------- Benchmarks ---------------------------------

MACHINE  = hash_machine()       # prepends security prefices by default
ENCODING = MACHINE.ENCODING     # utf-8
HASH     = MACHINE.hash         # SHA256


def leaf_benchmark():

    _leaf = Leaf(
        hash_function=HASH,
        encoding=ENCODING,
        record=b'some record...'
    )

    print(_size(_leaf))


def node_benchmark():
    """
    """

    def access_attribute_func(obj):
        def access_attribute():
            obj.stored_hash

        return access_attribute

    left = Leaf(
        hash_function=HASH,
        encoding=ENCODING,
        record=b'first record...'
    )

    right = Leaf(
        hash_function=HASH,
        encoding=ENCODING,
        record=b'second record...'
    )

    node = Node(
        hash_function=HASH,
        encoding=ENCODING,
        left=left,
        right=right
    )

    print(_size(left))

    print(_size(right))

    print(_size(node))

    print(timeit(access_attribute_func(left), number=10000))
    print(timeit(access_attribute_func(node), number=10000))

LENGTH = 10000
hash_type = 'sha256'
encoding = 'utf-32'

def tree_benchmark():
    """
    """

    tree = MerkleTree(hash_type='sha256', encoding=encoding)

    sys.stdout.write('\nTree size with 0 nodes (bytes): %d' % _size(tree))

    start = datetime.now()

    for _ in range(LENGTH):
        tree.encryptRecord('%d-th record' % _)

    sys.stdout.write('\nTime needed to genereate tree with %d nodes (secs): %f' % (LENGTH, _time_elapsed(start)))
    sys.stdout.write('\nTree size with %d leaves (bytes): %d' % (LENGTH, _size(tree)))
    sys.stdout.write('\nRoot size of tree with %d leaves (bytes): %d' % (LENGTH, _size(tree.root)))
    sys.stdout.write('\nLast leaf size of tree with %d leaves (bytes): %d' % (LENGTH, _size(tree.leaves[-1])))
    sys.stdout.write('\nIntermediate node size of tree with %d leaves (bytes): %d' % (LENGTH, _size(tree.leaves[10].child)))


# ------------------------------------ main ------------------------------------

def main():
    leaf_benchmark()
    node_benchmark()
    tree_benchmark()
    sys.exit(0)

if __name__ == "__main__":
    main()
