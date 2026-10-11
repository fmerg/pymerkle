from itertools import product
import pytest
from tests.conftest import tree_and_index

from pymerkle.utils import log2

from pymerkle import verify_inclusion, verify_consistency, InvalidChallenge, \
    InvalidProof


@pytest.mark.parametrize('tree, size1', tree_and_index())
def test_consistency_success(tree, size1):
    size2 = tree.get_size()
    proof = tree.prove_consistency(size1, size2)

    state1 = tree.get_state(size1)
    state2 = tree.get_state()

    verify_consistency(state1, state2, proof)


@pytest.mark.parametrize('tree, size1', tree_and_index(default_config=True))
def test_consistency_invalid_prior(tree, size1):
    size2 = tree.get_size()
    proof = tree.prove_consistency(size1, size2)

    state1 = tree.hash_raw(b'random')
    state2 = tree.get_state(size2)
    with pytest.raises(InvalidProof):
        verify_consistency(state1, state2, proof)


@pytest.mark.parametrize('tree, size1', tree_and_index(default_config=True))
def test_consistency_invalid_state(tree, size1):
    size2 = tree.get_size()
    proof = tree.prove_consistency(size1, size2)

    state1 = tree.get_state(size1)
    state2 = tree.hash_raw(b'random')
    with pytest.raises(InvalidProof):
        verify_consistency(state1, state2, proof)


@pytest.mark.parametrize('tree, size1', tree_and_index(default_config=True))
def test_consistency_invalid_challenge(tree, size1):
    size2 = tree.get_size()

    with pytest.raises(InvalidChallenge):
        tree.prove_consistency(size1, size2 + 1)

    with pytest.raises(InvalidChallenge):
        tree.prove_consistency(size1, -1)

    with pytest.raises(InvalidChallenge):
        tree.prove_consistency(size1 + 1, size1)

    with pytest.raises(InvalidChallenge):
        tree.prove_consistency(-1, size1)


@pytest.mark.parametrize('tree, size1', tree_and_index(default_config=True))
def test_consistency_wrong_type(tree, size1):
    size2 = tree.get_size()
    proof = tree.prove_consistency(size1, size2)

    state1 = tree.get_state(size1)
    state2 = tree.get_state(size2)

    with pytest.raises(InvalidProof):
        verify_consistency(state1.hex(), state2, proof)

    with pytest.raises(InvalidProof):
        verify_consistency(state1, 'n\u00f6n-ascii', proof)


def _all_nodes(tree):
    size = tree.get_size()
    return [tree._get_root(i, j) for i in range(size)
                                 for j in range(i + 1, size + 1)]


@pytest.mark.parametrize('size', range(2, 7))
def test_consistency_forged_prior_state(size):
    """
    Proofs whose rule and subset are chosen freely by the prover used to be
    accepted for prior states that are not genuine, e.g. the root of the right
    subtree. Only genuine prior states may pass verification.
    """
    from pymerkle import InmemoryTree, MerkleProof

    tree = InmemoryTree.init_from_entries([b'%d' % i for i in range(size)])
    state2 = tree.get_state()
    genuine = {tree.get_state(k) for k in range(1, size + 1)}

    nodes = _all_nodes(tree)
    bits = list(product([0, 1], repeat=2))
    for path, rule, subset, prior_size in product(product(nodes, repeat=2),
            bits, bits, range(1, size + 1)):
        proof = MerkleProof('sha256', True, size, list(rule), list(subset),
                list(path), prior_size=prior_size)
        try:
            verify_consistency(proof.retrieve_prior_state(), state2, proof)
        except InvalidProof:
            continue

        assert proof.retrieve_prior_state() in genuine


@pytest.mark.parametrize('tree, size1', tree_and_index(default_config=True))
def test_consistency_right_subtree_forgery(tree, size1):
    from pymerkle import MerkleProof

    size2 = tree.get_size()
    if size2 < 2:
        return

    k = 1 << log2(size2)
    if k == size2:
        k >>= 1
    lnode, rnode = tree._get_root(0, k), tree._get_root(k, size2)

    proof = MerkleProof(tree.algorithm, tree.security, size2, [1, 0], [1, 0],
            [rnode, lnode], prior_size=size1)
    with pytest.raises(InvalidProof):
        verify_consistency(rnode, tree.get_state(), proof)


@pytest.mark.parametrize('tree, size1', tree_and_index(default_config=True))
def test_consistency_expected_sizes(tree, size1):
    size2 = tree.get_size()
    proof = tree.prove_consistency(size1, size2)
    state1 = tree.get_state(size1)
    state2 = tree.get_state(size2)

    verify_consistency(state1, state2, proof, size1=size1, size2=size2)

    with pytest.raises(InvalidProof):
        verify_consistency(state1, state2, proof, size1=size1 + 1)

    with pytest.raises(InvalidProof):
        verify_consistency(state1, state2, proof, size2=size2 + 1)


@pytest.mark.parametrize('tree, size1', tree_and_index(default_config=True))
def test_consistency_tampered_prior_size(tree, size1):
    size2 = tree.get_size()
    proof = tree.prove_consistency(size1, size2)
    state1 = tree.get_state(size1)
    state2 = tree.get_state(size2)

    for prior_size in (None, 0, size2 + 1, '1'):
        proof.prior_size = prior_size
        with pytest.raises(InvalidProof):
            verify_consistency(state1, state2, proof)


@pytest.mark.parametrize('tree, size1', tree_and_index(default_config=True))
def test_consistency_serialization(tree, size1):
    from pymerkle import MerkleProof

    size2 = tree.get_size()
    proof = MerkleProof.deserialize(
        tree.prove_consistency(size1, size2).serialize())

    assert proof.prior_size == size1
    verify_consistency(tree.get_state(size1), tree.get_state(size2), proof)


@pytest.mark.parametrize('tree, size1', tree_and_index())
def test_consistency_structure(tree, size1):
    from pymerkle.proof import _consistency_structure

    size2 = tree.get_size()
    proof = tree.prove_consistency(size1, size2)

    assert _consistency_structure(size1, size2) == (proof.rule, proof.subset)
