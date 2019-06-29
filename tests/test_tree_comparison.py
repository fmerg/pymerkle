import pytest
import os
from pymerkle import MerkleTree, hashing, validateProof
from pymerkle.exceptions import InvalidTypesException, InvalidComparison

# ----------------------------------- Setuo -----------------------------------

HASH_TYPES = hashing.HASH_TYPES
ENCODINGS  = hashing.ENCODINGS

# Files to encrypt

short_APACHE_log  = os.path.join(os.path.dirname(__file__), 'logs/short_APACHE_log')
RED_HAT_LINUX_log = os.path.join(os.path.dirname(__file__), 'logs/RED_HAT_LINUX_log')

# ~ Generate trees (for all combinations of hash and encoding types)
# ~ along with valid parameters for inclusion test

trees_and_subtrees = []

for security in (True, False):
    for hash_type in HASH_TYPES:
        for encoding in ENCODINGS:

            tree = MerkleTree(
                hash_type=hash_type,
                encoding=encoding,
                security=security
            )

            tree.encryptFilePerLog(short_APACHE_log)
            old_hash, sublength = tree.rootHash, tree.length

            tree.encryptFilePerLog(RED_HAT_LINUX_log)

            trees_and_subtrees.append((tree, old_hash, sublength))


# --------------------------- Test exception cases  ---------------------------

@pytest.mark.parametrize("first, second", [(b'bytes', 'no_integer'), ('no_bytes', 0)])
def test_inclusion_test_InvalidTypesException(first, second):
    with pytest.raises(InvalidTypesException):
        MerkleTree().inclusionTest(first, second)

# -------------- Test success edge case with standard Merkle-Tree --------

def test_inclusion_test_failure_for_zero_leaves_case():
    assert MerkleTree().inclusionTest(old_hash=b'something', sublength=1) is False

def test_inclusion_test_edge_success_case():
    tree = MerkleTree()
    tree.encryptFilePerLog(short_APACHE_log)
    old_hash, sublength = tree.rootHash, tree.length
    tree.encryptFilePerLog(RED_HAT_LINUX_log)
    assert tree.inclusionTest(tree.rootHash, tree.length) is True

# ---------------- Test failure cases with standard Merkle-tree ----------


def test_inclusion_test_with_zero_sublength():
    with pytest.raises(InvalidComparison):
        tree.inclusionTest(b'anything...', 0)


def test_inclusion_test_with_sublength_exceeding_length():
    assert tree.inclusionTest(b'anything...', tree.length) is False


@pytest.mark.parametrize('sublength', list(i for i in range(1, tree.length)))
def test_inclusion_test_with_invalid_old_hash(sublength):
    assert tree.inclusionTest(
        b'anything except for the hash corresponding to the provided sublength',
        sublength) is False

# --------- Test intermediate success case for all possible tree types ---

@pytest.mark.parametrize("tree, old_hash, sublength", trees_and_subtrees)
def test_inclusion_test_success(tree, old_hash, sublength):
    assert tree.inclusionTest(old_hash, sublength) is True

# ------------------------- Test comparison operators -------------------------

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

@pytest.mark.parametrize("tree_1, tree_2", [(_0_leaves_tree, _0_leaves_tree_),
                                            (_0_leaves_tree, _1_leaves_tree_),
                                            (_1_leaves_tree, _1_leaves_tree_),
                                            (_0_leaves_tree, _2_leaves_tree_),
                                            (_1_leaves_tree, _2_leaves_tree_),
                                            (_2_leaves_tree, _2_leaves_tree_)])
def test_not___gt__(tree_1, tree_2):
    assert not tree_1 > tree_2

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


# -------------- Test inclusion for sublength equal to power of 2 --------

# ~ Passing the following tests indicates that the bug concerning inclusion tests (or,
# ~ implicitly, consistency proofs) for sublengths equal to powrs of 2 has been fixed
# ~ (in particular, the ``multi_hash`` function has been modified appropriately for
# ~ the case of one-member-sequences, so that this issue does not aris

# Initialize parametrization with the one-leaf tree

trees_and_later_states = [(
    MerkleTree('1'), MerkleTree(*[str(k) for k in range(1, j)])
) for j in range(2, 10)]

# Parametrize for the first 9 powers of 2 beginning from 2^1

for _power in range(1, 10):

    tree = MerkleTree(*[str(i) for i in range(2, 2**_power + 1)])

    for j in range(1, 10):
        trees_and_later_states.append(
            (
                tree,
                MerkleTree(*[str(k) for k in range(2, 2**_power + 1 + j)])
            )
        )


@pytest.mark.parametrize('_tree, _later_state', trees_and_later_states)
def test_inclusion_test_with_sublength_equal_to_power_of_2(_tree, _later_state):

    assert _later_state.inclusionTest(
        _tree.rootHash,
        _tree.length
    )


@pytest.mark.parametrize('_tree, _later_state', trees_and_later_states)
def test_consistency_proof_validation_with_sublength_equal_to_power_of_2(_tree, _later_state):

    assert validateProof(
        _later_state.rootHash,
        _later_state.consistencyProof(
            _tree.rootHash,
            _tree.length
        )
    )
