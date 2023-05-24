import pytest
from tests.conftest import option, resolve_backend

MerkleTree = resolve_backend(option)


def test_append_leaf():
    tree = MerkleTree()

    assert tree.get_size() == 0

    entries = ['a', 'b', 'c', 'd', 'e']
    for data in entries:
        index = tree.append_leaf(data)
        value = tree.get_leaf(index)

        assert index == tree.get_size()
        assert value == tree.hash_entry(data)
