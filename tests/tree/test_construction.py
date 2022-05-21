import pytest
import os
import json

from pymerkle.tree import MerkleTree, UnsupportedParameter


def test_unsupported_hash_type():
    with pytest.raises(UnsupportedParameter):
        MerkleTree(hash_type='anything unsupported...')


def test_unsupported_encoding():
    with pytest.raises(UnsupportedParameter):
        MerkleTree(encoding='anything unsupported...')


def test_MerkleTree_bool_implementation():
    assert not MerkleTree() and MerkleTree.init_from_records('some record')


def test_root_empty_tree_exception():
    assert not MerkleTree().root


def test_root_hash_for_empty_tree():
    assert not MerkleTree().root_hash


def test_root_hash_of_non_empty_MerkleTree():
    t = MerkleTree.init_from_records('first record')
    s = MerkleTree.init_from_records('first record', 'second record')
    assert t.root_hash == t.hash('first record') and \
        s.root_hash == s.hash(s.hash('first record'), s.hash('second record'))


def test_dimensions_of_empty_tree():
    tree = MerkleTree()
    assert (tree.length, tree.size, tree.height) == (0, 0, 0)


def test_dimensions_of_tree_with_three_leaves():
    tree = MerkleTree.init_from_records('first', 'second', 'third')
    assert (tree.length, tree.size, tree.height) == (3, 5, 2)
