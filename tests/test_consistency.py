from itertools import product
import pytest

from pymerkle import verify_inclusion, verify_consistency, InvalidChallenge, \
    InvalidProof, MerkleProof, InclusionProof, ConsistencyProof, \
    InmemoryTree
from pymerkle.core import _consistency_path_layout
from pymerkle.utils import floor_log2


def prove(tree, prior_size):
    """
    Returns the state corresponding to the provided size, the current state
    and the proof of consistency between them.
    """
    later_size = tree.get_size()

    return tree.get_root(prior_size), tree.get_root(later_size), \
        tree.prove_consistency(prior_size, later_size)


def test_consistency_success(tree, prior_size):
    prior_state, later_state, proof = prove(tree, prior_size)

    verify_consistency(prior_state, later_state, proof, security=tree.security)


@pytest.mark.default_config
def test_consistency_invalid_prior(tree, prior_size):
    _, later_state, proof = prove(tree, prior_size)
    prior_state = tree.hash_raw(b'random')
    with pytest.raises(InvalidProof):
        verify_consistency(prior_state, later_state, proof)


@pytest.mark.default_config
def test_consistency_invalid_state(tree, prior_size):
    prior_state, _, proof = prove(tree, prior_size)
    later_state = tree.hash_raw(b'random')
    with pytest.raises(InvalidProof):
        verify_consistency(prior_state, later_state, proof)


@pytest.mark.default_config
def test_consistency_invalid_challenge(tree, prior_size):
    later_size = tree.get_size()

    with pytest.raises(InvalidChallenge):
        tree.prove_consistency(prior_size, later_size + 1)

    with pytest.raises(InvalidChallenge):
        tree.prove_consistency(prior_size, -1)

    with pytest.raises(InvalidChallenge):
        tree.prove_consistency(prior_size + 1, prior_size)

    with pytest.raises(InvalidChallenge):
        tree.prove_consistency(-1, prior_size)


@pytest.mark.default_config
def test_consistency_wrong_type(tree, prior_size):
    prior_state, later_state, proof = prove(tree, prior_size)

    with pytest.raises(InvalidProof):
        verify_consistency(prior_state.hex(), later_state, proof)

    with pytest.raises(InvalidProof):
        verify_consistency(prior_state, 'n\u00f6n-ascii', proof)


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
    tree = InmemoryTree.init_from_entries([b'%d' % i for i in range(size)])
    later_state = tree.get_root()
    genuine = {tree.get_root(k) for k in range(1, size + 1)}

    nodes = _all_nodes(tree)
    bits = list(product([0, 1], repeat=2))
    for path, rule, subset, prior_size in product(product(nodes, repeat=2),
            bits, bits, range(1, size + 1)):
        proof = ConsistencyProof('sha256', True, size, prior_size, list(rule),
                list(subset), list(path))
        try:
            verify_consistency(proof.retrieve_prior_state(), later_state,
                proof)
        except InvalidProof:
            continue

        assert proof.retrieve_prior_state() in genuine


@pytest.mark.default_config
def test_consistency_right_subtree_forgery(tree, prior_size):
    later_size = tree.get_size()
    if later_size < 2:
        return

    k = 1 << floor_log2(later_size)
    if k == later_size:
        k >>= 1
    lnode, rnode = tree._get_root(0, k), tree._get_root(k, later_size)

    proof = ConsistencyProof(tree.algorithm, tree.security, later_size,
            prior_size, [1, 0], [1, 0], [rnode, lnode])
    with pytest.raises(InvalidProof):
        verify_consistency(rnode, tree.get_root(), proof)


@pytest.mark.default_config
def test_consistency_expected_sizes(tree, prior_size):
    later_size = tree.get_size()
    prior_state, later_state, proof = prove(tree, prior_size)

    verify_consistency(prior_state, later_state, proof, prior_size=prior_size,
        later_size=later_size)

    with pytest.raises(InvalidProof):
        verify_consistency(prior_state, later_state, proof,
            prior_size=prior_size + 1)

    with pytest.raises(InvalidProof):
        verify_consistency(prior_state, later_state, proof,
            later_size=later_size + 1)


@pytest.mark.default_config
def test_consistency_tampered_prior_size(tree, prior_size):
    prior_state, later_state, proof = prove(tree, prior_size)

    for invalid in (None, 0, tree.get_size() + 1, '1'):
        proof.prior_size = invalid
        with pytest.raises(InvalidProof):
            verify_consistency(prior_state, later_state, proof)


@pytest.mark.default_config
def test_consistency_serialization(tree, prior_size):
    prior_state, later_state, proof = prove(tree, prior_size)
    proof = MerkleProof.deserialize(proof.serialize())

    assert proof.prior_size == prior_size
    verify_consistency(prior_state, later_state, proof)


def test_consistency_path_layout(tree, prior_size):
    for later_size in range(prior_size, tree.get_size() + 1):
        rule, subset, path = tree._get_consistency_path_naive(prior_size,
            later_size)
        layout_rule, layout_subset, ranges = _consistency_path_layout(
            prior_size, later_size)

        assert (layout_rule, layout_subset) == (rule, subset)
        assert [tree._get_root_naive(*r) for r in ranges] == path


def test_consistency_security_downgrade():
    """
    With prefixes disabled by the prover and path elements of arbitrary
    length, the interior node preimage 0x01 || lnode used to be accepted as
    prior state of a secure tree.
    """
    tree = InmemoryTree.init_from_entries([b'a', b'b'])
    lnode, rnode = tree.get_leaf(1), tree.get_leaf(2)
    forged = b'\x01' + lnode

    proof = ConsistencyProof('sha256', False, 2, 1, [1, 0], [0, 1],
            [rnode, forged])
    assert proof.retrieve_prior_state() == forged
    assert proof.compute_root() == tree.get_root()

    with pytest.raises(InvalidProof):
        verify_consistency(forged, tree.get_root(), proof)

    with pytest.raises(InvalidProof):
        verify_consistency(forged, tree.get_root(), proof, security=False)


@pytest.mark.default_config
def test_consistency_expected_algorithm(tree, prior_size):
    prior_state, later_state, proof = prove(tree, prior_size)

    verify_consistency(prior_state, later_state, proof,
        algorithm=tree.algorithm)

    other = 'sha512' if tree.algorithm != 'sha512' else 'sha256'
    with pytest.raises(InvalidProof):
        verify_consistency(prior_state, later_state, proof, algorithm=other)


def test_consistency_huge_size():
    tree = InmemoryTree.init_from_entries([b'a', b'b', b'c'])
    proof = tree.prove_consistency(2)
    proof.size = 10 ** 100000

    with pytest.raises(InvalidProof):
        verify_consistency(tree.get_root(2), tree.get_root(), proof)


@pytest.mark.default_config
def test_consistency_proof_type(tree, prior_size):
    proof = tree.prove_consistency(prior_size)
    data = proof.serialize()

    assert data['type'] == 'consistency'
    assert isinstance(MerkleProof.deserialize(data), ConsistencyProof)
    assert isinstance(ConsistencyProof.deserialize(data), ConsistencyProof)

    with pytest.raises(InvalidProof):
        InclusionProof.deserialize(data)

    with pytest.raises(InvalidProof):
        verify_inclusion(tree.get_leaf(1), tree.get_root(), proof)
