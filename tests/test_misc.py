import pytest
from pymerkle.tree import MerkleTree
from pymerkle.hashing import UnsupportedParameter
from tests.conftest import option, all_configs


def test_bool():
    tree = MerkleTree()
    assert not tree
    assert not tree.get_root()

    tree = MerkleTree.init_from_entries('a')
    assert tree
    assert tree.get_root()


def test_dimensions():
    tree = MerkleTree()
    assert (tree.length, tree.size, tree.height) == (0, 0, 0)

    tree = MerkleTree.init_from_entries('a', 'b', 'c')
    assert (tree.length, tree.size, tree.height) == (3, 5, 2)


def test_construction_error():
    with pytest.raises(UnsupportedParameter):
        MerkleTree(algorithm='anything_unsupported')

    with pytest.raises(UnsupportedParameter):
        MerkleTree(encoding='anything_unsupported')
