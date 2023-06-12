from random import randint
import pytest

from pymerkle import SqliteTree as MerkleTree
from .conftest import option

defaults = {'warmup_rounds': 0, 'rounds': option.rounds}


tree = MerkleTree(option.dbfile, algorithm=option.algorithm)


def test_root(benchmark):

    def setup():
        start = randint(0, option.size - 2) if option.randomize else 0
        final = randint(start + 1, option.size) if option.randomize \
            else option.size

        return (start, final), {}

    benchmark.pedantic(tree.get_root, setup=setup, **defaults)


def test_state(benchmark):

    def setup():
        subsize = randint(1, option.size) if option.randomize \
            else option.size

        return (subsize,), {}

    benchmark.pedantic(tree.get_state, setup=setup, **defaults)


def test_inclusion(benchmark):

    def setup():
        subsize = option.size
        index = randint(1, subsize) if option.randomize else option.index

        return (index, subsize), {}

    benchmark.pedantic(tree.prove_inclusion, setup=setup, **defaults)


def test_consistency(benchmark):

    def setup():
        size2 = option.size
        size1 = randint(1, size2) if option.randomize else option.index

        return (size1, size2), {}

    benchmark.pedantic(tree.prove_consistency, setup=setup, **defaults)
