import pytest
import os
import json

from pymerkle.tree import MerkleTree, UnsupportedParameter


def test_unsupported_algorithm():
    with pytest.raises(UnsupportedParameter):
        MerkleTree(algorithm='anything unsupported...')


def test_unsupported_encoding():
    with pytest.raises(UnsupportedParameter):
        MerkleTree(encoding='anything unsupported...')


def test_MerkleTree_bool_implementation():
    assert not MerkleTree() and MerkleTree.init_from_records('something')


def test_root_empty_tree_exception():
    assert not MerkleTree().root


def test_root_hash_for_empty_tree():
    assert not MerkleTree().get_root_hash()


def test_root_hash_of_non_empty_MerkleTree():
    t = MerkleTree.init_from_records('a')
    s = MerkleTree.init_from_records('a', 'b')
    assert t.get_root_hash() == t.hash_data('a') and \
        s.get_root_hash() == s.hash_pair(s.hash_data('a'),
                s.hash_data('b'))


def test_dimensions_of_empty_tree():
    tree = MerkleTree()
    assert (tree.length, tree.size, tree.height) == (0, 0, 0)


def test_dimensions_of_tree_with_three_leaves():
    tree = MerkleTree.init_from_records('a', 'b', 'c')
    assert (tree.length, tree.size, tree.height) == (3, 5, 2)
