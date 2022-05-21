"""
Tests for inclusion-test and the comparison operators based upon it
"""

import pytest
import os

from pymerkle import MerkleTree
from pymerkle.hashing import SUPPORTED_HASH_TYPES

from tests.conftest import option, resolve_encodings

# Files to encrypt
child_dir = os.path.dirname(os.path.dirname(__file__))
short_APACHE_log = os.path.join(child_dir, 'logdata/short_APACHE_log')
RED_HAT_LINUX_log = os.path.join(child_dir, 'logdata/RED_HAT_LINUX_log')

trees_and_subtrees = []
for security in (True, False):
    for hash_type in SUPPORTED_HASH_TYPES:
        for encoding in resolve_encodings(option):
            config = {'hash_type': hash_type, 'encoding': encoding,
                      'security': security}
            tree = MerkleTree.init_from_records('a', 'b', 'c', 'd', 'e',
                                                config=config)
            state = tree.root_hash
            for record in ('f', 'g', 'h', 'k'):
                tree.encrypt(record)
            trees_and_subtrees.append((tree, state))


# Success edge case with standard Merkle-Tree

def test_has_previous_state_failure_for_zero_leaves_case():
    assert not MerkleTree().has_previous_state(b'something')


def test_has_previous_state_edge_success_case():
    tree = MerkleTree()
    tree.encrypt_file_per_line(short_APACHE_log)
    tree.encrypt_file_per_line(RED_HAT_LINUX_log)
    assert tree.has_previous_state(tree.root_hash)


# Failure cases with standard Merkle-tree

def test_has_previous_state_with_sublength_exceeding_length():
    assert not tree.has_previous_state(b'anything...')


@pytest.mark.parametrize('sublength', list(range(1, tree.length)))
def test_has_previous_state_with_invalid_state(sublength):
    assert not tree.has_previous_state(
        b'anything except for the hash corresponding to the provided sublength')


# Intermediate success case for all possible tree types

@pytest.mark.parametrize('tree, checksum', trees_and_subtrees)
def test_has_previous_state_success(tree, checksum):
    assert tree.has_previous_state(checksum)


# Comparison operators

_0_leaves_tree = MerkleTree.init_from_records()
_1_leaves_tree = MerkleTree.init_from_records('a')
_2_leaves_tree = MerkleTree.init_from_records('a', 'b')

_0_leavestree2 = MerkleTree.init_from_records()
_1_leavestree2 = MerkleTree.init_from_records('a')
_2_leavestree2 = MerkleTree.init_from_records('a', 'b')


@pytest.mark.parametrize('tree_1, tree_2', [(_0_leaves_tree, _0_leavestree2),
                                            (_1_leaves_tree, _1_leavestree2),
                                            (_2_leaves_tree, _2_leavestree2)])
def test___eq__(tree_1, tree_2):
    assert tree_1 == tree_2


@pytest.mark.parametrize('tree_1, tree_2', [(_0_leaves_tree, _1_leavestree2),
                                            (_1_leaves_tree, _0_leavestree2),
                                            (_1_leaves_tree, _2_leavestree2),
                                            (_0_leaves_tree, _2_leavestree2)])
def test___ne__(tree_1, tree_2):
    assert tree_1 != tree_2


@pytest.mark.parametrize('tree_1, tree_2', [(_0_leaves_tree, _0_leavestree2),
                                            (_1_leaves_tree, _0_leavestree2),
                                            (_2_leaves_tree, _0_leavestree2),
                                            (_1_leaves_tree, _1_leavestree2),
                                            (_2_leaves_tree, _1_leavestree2),
                                            (_2_leaves_tree, _2_leavestree2)])
def test___ge__(tree_1, tree_2):
    assert tree_1 >= tree_2


@pytest.mark.parametrize('tree_1, tree_2', [(_0_leaves_tree, _1_leavestree2),
                                            (_0_leaves_tree, _2_leavestree2),
                                            (_1_leaves_tree, _2_leavestree2)])
def test_not___ge__(tree_1, tree_2):
    assert not tree_1 >= tree_2


@pytest.mark.parametrize('tree_1, tree_2', [(_1_leaves_tree, _0_leavestree2),
                                            (_2_leaves_tree, _0_leavestree2),
                                            (_2_leaves_tree, _1_leavestree2)])
def test___gt__(tree_1, tree_2):
    assert tree_1 > tree_2


@pytest.mark.parametrize('tree_1, tree_2', [(_0_leavestree2, _0_leaves_tree),
                                            (_0_leavestree2, _1_leaves_tree),
                                            (_1_leavestree2, _1_leaves_tree),
                                            (_0_leavestree2, _2_leaves_tree),
                                            (_1_leavestree2, _2_leaves_tree),
                                            (_2_leavestree2, _2_leaves_tree)])
def test_not___gt__(tree_1, tree_2):
    assert not tree_1 > tree_2


@pytest.mark.parametrize('tree_1, tree_2', [(_0_leaves_tree, _0_leavestree2),
                                            (_0_leaves_tree, _1_leavestree2),
                                            (_0_leaves_tree, _2_leavestree2),
                                            (_1_leaves_tree, _1_leavestree2),
                                            (_1_leaves_tree, _2_leavestree2),
                                            (_2_leaves_tree, _2_leavestree2)])
def test___le__(tree_1, tree_2):
    assert tree_1 <= tree_2


@pytest.mark.parametrize('tree_1, tree_2', [(_1_leavestree2, _0_leaves_tree),
                                            (_2_leavestree2, _0_leaves_tree),
                                            (_2_leavestree2, _1_leaves_tree)])
def test_not___le__(tree_1, tree_2):
    assert not tree_1 <= tree_2


@pytest.mark.parametrize('tree_1, tree_2', [(_0_leavestree2, _1_leaves_tree),
                                            (_0_leavestree2, _2_leaves_tree),
                                            (_1_leavestree2, _2_leaves_tree)])
def test___lt__(tree_1, tree_2):
    assert tree_1 < tree_2


@pytest.mark.parametrize('tree_1, tree_2', [(_0_leavestree2, _0_leaves_tree),
                                            (_1_leavestree2, _0_leaves_tree),
                                            (_1_leavestree2, _1_leaves_tree),
                                            (_2_leavestree2, _0_leaves_tree),
                                            (_2_leavestree2, _1_leaves_tree),
                                            (_2_leavestree2, _2_leaves_tree)])
def test_not___lt__(tree_1, tree_2):
    assert not tree_1 < tree_2


# Invalid comparison tests

def test___eq___TypeError():
    with pytest.raises(TypeError):
        MerkleTree() == 'anything except for a Merkle-tree'


def test_not___eq___TypeError():
    with pytest.raises(TypeError):
        MerkleTree() != 'anything except for a Merkle-tree'


def test___ge___TypeError():
    with pytest.raises(TypeError):
        MerkleTree() >= 'anything except for a Merkle-tree'


def test_not___ge___TypeError():
    with pytest.raises(TypeError):
        not MerkleTree() >= 'anything except for a Merkle-tree'


def test___le___TypeError():
    with pytest.raises(TypeError):
        MerkleTree() <= 'anything except for a Merkle-tree'


def test_not___le___TypeError():
    with pytest.raises(TypeError):
        not MerkleTree() <= 'anything except for a Merkle-tree'


def test___gt___TypeError():
    with pytest.raises(TypeError):
        MerkleTree() > 'anything except for a Merkle-tree'


def test_not___gt___TypeError():
    with pytest.raises(TypeError):
        not MerkleTree() > 'anything except for a Merkle-tree'


def test___lt___TypeError():
    with pytest.raises(TypeError):
        MerkleTree() < 'anything except for a Merkle-tree'


def test_not___lt___TypeError():
    with pytest.raises(TypeError):
        not MerkleTree() < 'anything except for a Merkle-tree'


# Test inclusion for sublength equal to power of 2

# Initialize parametrization with the one-leaf tree and parametrize
# for the first 9 powers of 2 beginning from 2 ^ 1
trees__later_states = [(
    MerkleTree.init_from_records('1'),
    MerkleTree.init_from_records(*[str(k) for k in range(1, j)])
) for j in range(2, 10)]
for power in range(1, 10):
    tree = MerkleTree.init_from_records(
        *[str(i) for i in range(2, 2 ** power + 1)])
    for j in range(1, 10):
        trees__later_states.append(
            (
                tree,
                MerkleTree.init_from_records(
                    *[str(k) for k in range(2, 2 ** power + 1 + j)])
            )
        )


@pytest.mark.parametrize('tree, later_state', trees__later_states)
def test_has_previous_state_with_sublength_equal_to_power_of_2(tree, later_state):
    assert later_state.has_previous_state(tree.root_hash)


@pytest.mark.parametrize('tree, later_state', trees__later_states)
def test_consistency_proof_verification_with_sublength_equal_to_power_of_2(
        tree, later_state):
    proof = later_state.generate_consistency_proof(tree.root_hash)
    assert proof.verify(later_state.root_hash)
