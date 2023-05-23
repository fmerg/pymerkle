import pytest
from pymerkle.tree import MerkleTree
from tests.conftest import option, all_configs


def test_append_leaf():
    tree = MerkleTree()

    assert tree.get_size() == 0

    entries = ['a', 'b', 'c', 'd', 'e']
    for (i, data) in enumerate(entries, start=1):
        index = tree.append_leaf(data)
        value = tree.get_leaf(index)

        assert index == i
        assert value == tree.hash_entry(data)
