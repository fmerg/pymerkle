import pytest
import os
from pymerkle import MerkleTree, hashing, encodings

# --------- Test intermediate success case for all possible tree types ---

HASH_TYPES = hashing.HASH_TYPES
ENCODINGS = encodings.ENCODINGS

# Directory containing this script
current_dir = os.path.dirname(os.path.abspath(__file__))

# Generate trees (for all combinations of hash and encoding types)
# along with valid parameters for inclusion test
trees_and_subtrees = []
for security in (True, False):
    for hash_type in HASH_TYPES:
        for encoding in ENCODINGS:
            tree = MerkleTree(
                hash_type=hash_type,
                encoding=encoding,
                security=security,
                log_dir=os.path.join(current_dir, 'logs'))
            tree.encryptLog('short_APACHE_log')
            old_hash, sublength = tree.rootHash(), tree.length()
            tree.encryptLog('RED_HAT_LINUX_log')
            trees_and_subtrees.append((tree, old_hash, sublength))


@pytest.mark.parametrize("tree, old_hash, sublength", trees_and_subtrees)
def test_inclusion_test_with_valid_parameters(tree, old_hash, sublength):
    assert tree.inclusionTest(old_hash, sublength) is True

# -------------- Test success edge case with standard Merkle-Tree --------


tree = MerkleTree(log_dir=os.path.join(current_dir, 'logs'))
tree.encryptLog('short_APACHE_log')
old_hash, sublength = tree.rootHash(), tree.length()
tree.encryptLog("RED_HAT_LINUX_log")


def test_inclusion_test_edge_success_case():
    assert tree.inclusionTest(tree.rootHash(), tree.length()) is True

# --------------- Failure tests cases with standard Merkle-tree ----------


def test_inclusion_test_with_zero_sublength():
    assert tree.inclusionTest(b'anything...', 0) is False


def test_inclusion_test_with_sublength_exceeding_length():
    assert tree.inclusionTest(b'anything...', tree.length()) is False


@pytest.mark.parametrize('sublength', list(i for i in range(1, tree.length())))
def test_inclusion_test_with_invalid_old_hash(sublength):
    assert tree.inclusionTest(
        b'anything except for the hash corresponding to the provided sublength',
        sublength) is False

# -------------- Test inclusion for sublength equal to power of 2 --------

# ~ Passing the following tests indicates that the bug concerning inclusion
# ~ tests (or, implicitly, consistency proofs) for sublengths equal to
# ~ powers of 2 has been fixed (in particular, the ``multi_hash``
# ~ functionality has been modified appropriately for the case of
# ~ one-member-sequences, so that this issue does not arise)


# Initialize parametrization with the empty tree
trees_and_later_states = [(
    MerkleTree(), MerkleTree(*[str(k) for k in range(1, j)])
) for j in range(0, 10)]

# Parametrize for the first 10 powers of 2
for power in range(0, 10):
    tree = MerkleTree(*[str(i) for i in range(1, 2**power + 1)])
    for j in range(0, 10):
        trees_and_later_states.append((
            tree,
            MerkleTree(*[str(k) for k in range(1, 2**power + 1 + j)])
        ))


@pytest.mark.parametrize('tree, later_state', trees_and_later_states)
def test_inclusion_test_with_sublength_equal_to_power_of_2(tree, later_state):
    assert later_state.inclusionTest(
        old_hash=tree.rootHash(),
        sublength=tree.length()) is True
