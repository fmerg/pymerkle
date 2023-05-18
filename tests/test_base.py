import pytest
from pymerkle.tree import MerkleTree
from pymerkle.hashing import UnsupportedParameter
from tests.conftest import option, all_configs


def test_append():
    tree = MerkleTree()

    assert not tree and not tree.get_state()
    assert tree.get_size() == 0

    checksum = tree.append_leaf('a')
    assert checksum == tree.hash_entry('a')
    assert tree.get_size() == 1

    checksum = tree.append_leaf('b')
    assert checksum == tree.hash_entry('b')
    assert tree.get_size() == 2

    checksum = tree.append_leaf('c')
    assert checksum == tree.hash_entry('c')
    assert tree.get_size() == 3

    assert tree and tree.get_state()


def test_unsupported():
    with pytest.raises(UnsupportedParameter):
        MerkleTree(algorithm='anything_unsupported')

    with pytest.raises(UnsupportedParameter):
        MerkleTree(encoding='anything_unsupported')
