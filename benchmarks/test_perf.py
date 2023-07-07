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
        size = randint(1, option.size) if option.randomize \
            else option.size

        return (size,), {}

    benchmark.pedantic(tree.get_state, setup=setup, **defaults)


def test_inclusion(benchmark):

    def setup():
        size = option.size
        index = randint(1, size) if option.randomize else option.index

        return (index, size), {}

    benchmark.pedantic(tree.prove_inclusion, setup=setup, **defaults)


def test_consistency(benchmark):

    def setup():
        rsize = option.size
        lsize = randint(1, rsize) if option.randomize else option.index

        return (lsize, rsize), {}

    benchmark.pedantic(tree.prove_consistency, setup=setup, **defaults)
