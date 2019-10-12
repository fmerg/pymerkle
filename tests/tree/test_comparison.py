"""
Tests for inclusion-test and the comparison operators based upon it
"""

import pytest
import os
from pymerkle import MerkleTree, hashing, validateProof
from pymerkle.exceptions import InvalidTypes, InvalidComparison
from tests.config import ENCODINGS

HASH_TYPES = hashing.HASH_TYPES

# Files to encrypt
parent_dir = os.path.dirname(os.path.dirname(__file__))
short_APACHE_log  = os.path.join(parent_dir, 'log_files/short_APACHE_log')
RED_HAT_LINUX_log = os.path.join(parent_dir, 'log_files/RED_HAT_LINUX_log')

trees_and_subtrees = []
for security in (True, False):
    for hash_type in HASH_TYPES:
        for encoding in ENCODINGS:
            tree = MerkleTree(
                'a', 'b', 'c', 'd', 'e',
                hash_type=hash_type,
                encoding=encoding,
                security=security
            )
            subhash, sublength = tree.rootHash, tree.length
            for record in ('f', 'g', 'h', 'k'):
                tree.encryptRecord(record)
            trees_and_subtrees.append((tree, subhash, sublength))


# Exception cases

@pytest.mark.parametrize("first, second", [(b'bytes', 'no_integer'), ('no_bytes', 0)])
def test_inclusion_test_InvalidTypes(first, second):
    with pytest.raises(InvalidTypes):
        MerkleTree().inclusionTest(first, second)


# Success edge case with standard Merkle-Tree

def test_inclusion_test_failure_for_zero_leaves_case():
    assert MerkleTree().inclusionTest(subhash=b'something', sublength=1) is False

def test_inclusion_test_edge_success_case():
    tree = MerkleTree()
    tree.encryptFilePerLog(short_APACHE_log)
    subhash, sublength = tree.rootHash, tree.length
    tree.encryptFilePerLog(RED_HAT_LINUX_log)
    assert tree.inclusionTest(tree.rootHash, tree.length) is True


# Failure cases with standard Merkle-tree

def test_inclusion_test_with_zero_sublength():
    with pytest.raises(InvalidComparison):
        tree.inclusionTest(b'anything...', 0)

def test_inclusion_test_with_sublength_exceeding_length():
    assert tree.inclusionTest(b'anything...', tree.length) is False

@pytest.mark.parametrize('sublength', list(range(1, tree.length)))
def test_inclusion_test_with_invalid_subhash(sublength):
    assert tree.inclusionTest(
        subhash=b'anything except for the hash corresponding to the provided sublength',
        sublength=sublength
    ) is False


# Intermediate success case for all possible tree types

@pytest.mark.parametrize("tree, subhash, sublength", trees_and_subtrees)
def test_inclusion_test_success(tree, subhash, sublength):
    assert tree.inclusionTest(subhash, sublength) is True


# Comparison operators

_0_leaves_tree  = MerkleTree()
_0_leaves_tree_ = MerkleTree()
_1_leaves_tree  = MerkleTree('a')
_1_leaves_tree_ = MerkleTree('a')
_2_leaves_tree  = MerkleTree('a', 'b')
_2_leaves_tree_ = MerkleTree('a', 'b')

@pytest.mark.parametrize("tree_1, tree_2", [(_0_leaves_tree, _0_leaves_tree_),
                                            (_1_leaves_tree, _1_leaves_tree_),
                                            (_2_leaves_tree, _2_leaves_tree_)])
def test___eq__(tree_1, tree_2):
    assert tree_1 == tree_2

@pytest.mark.parametrize("tree_1, tree_2", [(_0_leaves_tree, _1_leaves_tree_),
                                            (_1_leaves_tree, _0_leaves_tree_),
                                            (_1_leaves_tree, _2_leaves_tree_),
                                            (_0_leaves_tree, _2_leaves_tree_)])
def test___ne__(tree_1, tree_2):
    assert tree_1 != tree_2

@pytest.mark.parametrize("tree_1, tree_2", [(_0_leaves_tree, _0_leaves_tree_),
                                            (_1_leaves_tree, _0_leaves_tree_),
                                            (_2_leaves_tree, _0_leaves_tree_),
                                            (_1_leaves_tree, _1_leaves_tree_),
                                            (_2_leaves_tree, _1_leaves_tree_),
                                            (_2_leaves_tree, _2_leaves_tree_)])
def test___ge__(tree_1, tree_2):
    assert tree_1 >= tree_2

@pytest.mark.parametrize("tree_1, tree_2", [(_0_leaves_tree, _1_leaves_tree_),
                                            (_0_leaves_tree, _2_leaves_tree_),
                                            (_1_leaves_tree, _2_leaves_tree_)])
def test_not___ge__(tree_1, tree_2):
    assert not tree_1 >= tree_2

@pytest.mark.parametrize("tree_1, tree_2", [(_1_leaves_tree, _0_leaves_tree_),
                                            (_2_leaves_tree, _0_leaves_tree_),
                                            (_2_leaves_tree, _1_leaves_tree_)])
def test___gt__(tree_1, tree_2):
    assert tree_1 > tree_2

@pytest.mark.parametrize("tree_1, tree_2", [(_0_leaves_tree_, _0_leaves_tree),
                                            (_0_leaves_tree_, _1_leaves_tree),
                                            (_1_leaves_tree_, _1_leaves_tree),
                                            (_0_leaves_tree_, _2_leaves_tree),
                                            (_1_leaves_tree_, _2_leaves_tree),
                                            (_2_leaves_tree_, _2_leaves_tree)])
def test_not___gt__(tree_1, tree_2):
    assert not tree_1 > tree_2

@pytest.mark.parametrize("tree_1, tree_2", [(_0_leaves_tree, _0_leaves_tree_),
                                            (_0_leaves_tree, _1_leaves_tree_),
                                            (_0_leaves_tree, _2_leaves_tree_),
                                            (_1_leaves_tree, _1_leaves_tree_),
                                            (_1_leaves_tree, _2_leaves_tree_),
                                            (_2_leaves_tree, _2_leaves_tree_)])
def test___le__(tree_1, tree_2):
    assert tree_1 <= tree_2

@pytest.mark.parametrize("tree_1, tree_2", [(_1_leaves_tree_, _0_leaves_tree),
                                            (_2_leaves_tree_, _0_leaves_tree),
                                            (_2_leaves_tree_, _1_leaves_tree)])
def test_not___le__(tree_1, tree_2):
    assert not tree_1 <= tree_2

@pytest.mark.parametrize("tree_1, tree_2", [(_0_leaves_tree_, _1_leaves_tree),
                                            (_0_leaves_tree_, _2_leaves_tree),
                                            (_1_leaves_tree_, _2_leaves_tree)])
def test___lt__(tree_1, tree_2):
    assert tree_1 < tree_2

@pytest.mark.parametrize("tree_1, tree_2", [(_0_leaves_tree_, _0_leaves_tree),
                                            (_1_leaves_tree_, _0_leaves_tree),
                                            (_1_leaves_tree_, _1_leaves_tree),
                                            (_2_leaves_tree_, _0_leaves_tree),
                                            (_2_leaves_tree_, _1_leaves_tree),
                                            (_2_leaves_tree_, _2_leaves_tree)])
def test_not___lt__(tree_1, tree_2):
    assert not tree_1 < tree_2


# Invalid comparison tests

def test___eq___InvalidComparison():
    with pytest.raises(InvalidComparison):
        MerkleTree() == 'anything except for a Merkle-tree'

def test_not___eq___InvalidComparison():
    with pytest.raises(InvalidComparison):
        MerkleTree() != 'anything except for a Merkle-tree'

def test___ge___InvalidComparison():
    with pytest.raises(InvalidComparison):
        MerkleTree() >= 'anything except for a Merkle-tree'

def test_not___ge___InvalidComparison():
    with pytest.raises(InvalidComparison):
        not MerkleTree() >= 'anything except for a Merkle-tree'

def test___le___InvalidComparison():
    with pytest.raises(InvalidComparison):
        MerkleTree() <= 'anything except for a Merkle-tree'

def test_not___le___InvalidComparison():
    with pytest.raises(InvalidComparison):
        not MerkleTree() <= 'anything except for a Merkle-tree'

def test___gt___InvalidComparison():
    with pytest.raises(InvalidComparison):
        MerkleTree() > 'anything except for a Merkle-tree'

def test_not___gt___InvalidComparison():
    with pytest.raises(InvalidComparison):
        not MerkleTree() > 'anything except for a Merkle-tree'

def test___lt___InvalidComparison():
    with pytest.raises(InvalidComparison):
        MerkleTree() < 'anything except for a Merkle-tree'

def test_not___lt___InvalidComparison():
    with pytest.raises(InvalidComparison):
        not MerkleTree() < 'anything except for a Merkle-tree'


# Inclusion for sublength equal to power of 2

# ~ Passing the following tests indicates that the bug concerning inclusion tests (or,
# ~ implicitly, consistency proofs) for sublengths equal to powers of 2 has been fixed
# ~ (in particular, the ``multi_hash`` function has been modified appropriately for
# ~ the case of one-member-sequences, so that this issue does not arise)

# Initialize parametrization with the one-leaf tree and parametrize
# for the first 9 powers of 2 beginning from 2 ^ 1
__trees__later_states = [(
    MerkleTree('1'), MerkleTree(*[str(k) for k in range(1, j)])
) for j in range(2, 10)]
for power in range(1, 10):
    tree = MerkleTree(*[str(i) for i in range(2, 2 ** power + 1)])
    for j in range(1, 10):
        __trees__later_states.append(
            (
                tree,
                MerkleTree(*[str(k) for k in range(2, 2 ** power + 1 + j)])
            )
        )

@pytest.mark.parametrize('tree, later_state', __trees__later_states)
def test_inclusion_test_with_sublength_equal_to_power_of_2(tree, later_state):
    assert later_state.inclusionTest(tree.rootHash, tree.length)

@pytest.mark.parametrize('tree, later_state', __trees__later_states)
def test_consistency_proof_validation_with_sublength_equal_to_power_of_2(tree, later_state):
    assert validateProof(
        later_state.rootHash,
        later_state.consistencyProof(tree.rootHash, tree.length)
    )
