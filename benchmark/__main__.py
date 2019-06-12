# -*- coding: utf-8 -*-
#!/usr/bin/env python

import os, sys, inspect, logging
from timeit import timeit
from numbers import Number
from collections import Set, Mapping, deque
from datetime import datetime

# Make pymerkle importable
current_dir = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
parent_dir = os.path.dirname(current_dir)
sys.path.insert(0, parent_dir)

from pymerkle import MerkleTree
from pymerkle.hashing import hash_machine
from pymerkle.nodes import Node, Leaf

zero_depth_bases = (str, bytes, Number, range, bytearray)
iteritems = 'items'


def getsize(obj_0):
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
            pass  # bypass remaining control flow and return
        elif isinstance(obj, (tuple, list, Set, deque)):
            size += sum(inner(i) for i in obj)
        elif isinstance(obj, Mapping) or hasattr(obj, iteritems):
            size += sum(inner(k) + inner(v)
                        for k, v in getattr(obj, iteritems)())
        # Check for custom object instances - may subclass above too
        if hasattr(obj, '__dict__'):
            size += inner(vars(obj))
        if hasattr(obj, '__slots__'):  # can have __slots__ with __dict__
            size += sum(inner(getattr(obj, s))
                        for s in obj.__slots__ if hasattr(obj, s))
        return size
    return inner(obj_0)


def _time_elapsed(start):
    """
    """
    return (datetime.now() - start).total_seconds()


def get_logger():
    """
    """
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    streamHandler = logging.StreamHandler()
    streamHandler.setLevel(logging.INFO)
    streamFormatter = logging.Formatter('[%(levelname)s] %(message)s')
    streamHandler.setFormatter(streamFormatter)
    logger.addHandler(streamHandler)
    return logger


def tree_benchmark():
    t = MerkleTree()
    print(getsize(t))
    start = datetime.now()
    for i in range(200000):
        t.encryptRecord('%d-th record' % i)
    print(_time_elapsed(start))
    print(getsize(t))

MACHINE = hash_machine()        # prepends security prefices by default
ENCODING = MACHINE.ENCODING     # utf-8
HASH = MACHINE.hash             # SHA256

def leaf_benchmark():
    _leaf = Leaf(hash_function=HASH,
         encoding=ENCODING,
         record=b'some record...')
    print(getsize(_leaf))

def node_benchmark():

    def get_set_delete_fn(obj):
        def get_set_delete():
            obj.stored_hash = 'foo'
            obj.stored_hash
            del obj.stored_hash
        return get_set_delete

    left = Leaf(hash_function=HASH,
         encoding=ENCODING,
         record=b'first record...')
    right = Leaf(hash_function=HASH,
         encoding=ENCODING,
         record=b'second record...')
    node = Node(hash_function=HASH,
         encoding=ENCODING,
         left=left,
         right=right)
    print(getsize(left))
    # print(repr(left))
    print(getsize(right))
    # print(repr(right))
    print(getsize(node))
    # print(repr(node))
    print(timeit(get_set_delete_fn(left), number=1000))#get_set_delete_fn(slotted))
    print(timeit(get_set_delete_fn(node), number=1000))#get_set_delete_fn(slotted))


if __name__ == "__main__":
    # tree_benchmark()
    # leaf_benchmark()
    node_benchmark()
    sys.exit(0)
