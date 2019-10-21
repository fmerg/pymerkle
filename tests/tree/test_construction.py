import pytest
import os
import json

from pymerkle.core import MerkleTree
from pymerkle.exceptions import (EmptyTreeException, UnsupportedHashType,
    UnsupportedEncoding, LeafConstructionError, UndecodableRecord, )


__undecodableArguments = [
    (b'\xc2', 'ascii', True),
    (b'\xc2', 'ascii', False),
    (b'\x72', 'cp424', True),
    (b'\x72', 'cp424', False),
    (b'\xc2', 'hz', True),
    (b'\xc2', 'hz', False),
    (b'\xc2', 'utf_7', True),
    (b'\xc2', 'utf_7', False),
    (b'\x74', 'utf_16', True),
    (b'\x74', 'utf_16', False),
    (b'\x74', 'utf_16_le', True),
    (b'\x74', 'utf_16_le', False),
    (b'\x74', 'utf_16_be', True),
    (b'\x74', 'utf_16_be', False),
    (b'\x74', 'utf_32', True),
    (b'\x74', 'utf_32', False),
    (b'\x74', 'utf_32_le', True),
    (b'\x74', 'utf_32_le', False),
    (b'\x74', 'utf_32_be', True),
    (b'\x74', 'utf_32_be', False),
    (b'\xc2', 'iso2022_jp', True),
    (b'\xc2', 'iso2022_jp', False),
    (b'\xc2', 'iso2022_jp_1', True),
    (b'\xc2', 'iso2022_jp_1', False),
    (b'\xc2', 'iso2022_jp_2', True),
    (b'\xc2', 'iso2022_jp_2', False),
    (b'\xc2', 'iso2022_jp_3', True),
    (b'\xc2', 'iso2022_jp_3', False),
    (b'\xc2', 'iso2022_jp_ext', True),
    (b'\xc2', 'iso2022_jp_ext', False),
    (b'\xc2', 'iso2022_jp_2004', True),
    (b'\xc2', 'iso2022_jp_2004', False),
    (b'\xc2', 'iso2022_kr', True),
    (b'\xc2', 'iso2022_kr', False),
    (b'\xae', 'iso8859_3', True),
    (b'\xae', 'iso8859_3', False),
    (b'\xb6', 'iso8859_6', True),
    (b'\xb6', 'iso8859_6', False),
    (b'\xae', 'iso8859_7', True),
    (b'\xae', 'iso8859_7', False),
    (b'\xc2', 'iso8859_8', True),
    (b'\xc2', 'iso8859_8', False),
]


# Construction

def test_UnsupportedHashType():
    """
    Tests that a `UnsupportedHashType` is raised when a Merkle-tree
    for an unsupported hash-type is requested
    """
    with pytest.raises(UnsupportedHashType):
        MerkleTree(hash_type='anything unsupported...')


def test_UnsupportedEncoding():
    """
    Tests that a `UnsupportedEncoding` is raised when a Merkle-tree
    for an unsupported encoding type is requested
    """
    with pytest.raises(UnsupportedEncoding):
        MerkleTree(encoding='anything unsupported...')


@pytest.mark.parametrize('byte, encoding, security', __undecodableArguments)
def test_UndecodableRecord_upon_tree_construction(byte, encoding, security):
    with pytest.raises(UndecodableRecord):
        MerkleTree('a', byte, encoding=encoding, security=security,
            raw_bytes=False)


# Clearance

def test_clear():
    tree = MerkleTree('a', 'b', 'c')
    tree.clear()
    with pytest.raises(EmptyTreeException):
        tree.root
    assert not tree.leaves and not tree.nodes


# Boolean implementation and root-hash

def test_MerkleTree_bool_implementation():
    """
    Tests that a Merkle-tree is equivalent to `False` iff it is empty
    """
    assert not MerkleTree() and MerkleTree('some record')

def test_root_empty_tree_exception():
    """
    Tests `EmptyTreeException` upon requesting the root of an empty Merkle-tree
    """
    with pytest.raises(EmptyTreeException):
        MerkleTree().root

def test_rootHash_empty_tree_exception():
    """
    Tests `EmptyTreeException` upon requesting the root-hash
    of an empty Merkle-tree
    """
    with pytest.raises(EmptyTreeException):
        MerkleTree().rootHash

def test_rootHash_of_non_empty_MerkleTree():
    """
    Tests the root-hash of a Merkle-tree with one and two leaves
    """
    t = MerkleTree('first record')
    s = MerkleTree('first record', 'second record')
    assert t.rootHash == t.hash('first record') and \
        s.rootHash == s.hash(s.hash('first record'), s.hash('second record'))


# Update tests

def test_LeafConstructionError_upon_update():
    """
    Tests that a `LeafConstructionError` is raised if both `record` and
    `digest` are provided as arguments to the `MerkleTree.update()` method
    """
    t = MerkleTree()
    with pytest.raises(LeafConstructionError):
        t.update(
            record='some record',
            digest='540ef8fc9eefa3ec0fbe55bc5d10dbea03d5bac5591b3d7db3af79ec24b3f74c'
        )


@pytest.mark.parametrize('byte, encoding, security', __undecodableArguments)
def test_UndecodableRecord_upon_update(byte, encoding, security):
    t = MerkleTree('a', 'b', 'c', encoding=encoding, security=security,
        raw_bytes=False)
    with pytest.raises(UndecodableRecord):
        t.update(record=byte)


def test_properties_of_empty_tree():
    tree = MerkleTree()
    assert (tree.length, tree.size, tree.height) == (0, 0, 0)

def test_properties_of_tree_with_three_leaves():
    tree = MerkleTree('first', 'second', 'third')
    assert (tree.length, tree.size, tree.height) == (3, 5, 2)
