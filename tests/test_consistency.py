from itertools import product
import pytest

from pymerkle.utils import log2

from pymerkle import verify_inclusion, verify_consistency, InvalidChallenge, \
    InvalidProof


def test_consistency_success(tree, size1):
    size2 = tree.get_size()
    proof = tree.prove_consistency(size1, size2)

    state1 = tree.get_state(size1)
    state2 = tree.get_state()

    verify_consistency(state1, state2, proof, security=tree.security)


@pytest.mark.default_config
def test_consistency_invalid_prior(tree, size1):
    size2 = tree.get_size()
    proof = tree.prove_consistency(size1, size2)

    state1 = tree.hash_raw(b'random')
    state2 = tree.get_state(size2)
    with pytest.raises(InvalidProof):
        verify_consistency(state1, state2, proof)


@pytest.mark.default_config
def test_consistency_invalid_state(tree, size1):
    size2 = tree.get_size()
    proof = tree.prove_consistency(size1, size2)

    state1 = tree.get_state(size1)
    state2 = tree.hash_raw(b'random')
    with pytest.raises(InvalidProof):
        verify_consistency(state1, state2, proof)


@pytest.mark.default_config
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


@pytest.mark.default_config
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
    from pymerkle import InmemoryTree, ConsistencyProof

    tree = InmemoryTree.init_from_entries([b'%d' % i for i in range(size)])
    state2 = tree.get_state()
    genuine = {tree.get_state(k) for k in range(1, size + 1)}

    nodes = _all_nodes(tree)
    bits = list(product([0, 1], repeat=2))
    for path, rule, subset, prior_size in product(product(nodes, repeat=2),
            bits, bits, range(1, size + 1)):
        proof = ConsistencyProof('sha256', True, size, prior_size, list(rule),
                list(subset), list(path))
        try:
            verify_consistency(proof.retrieve_prior_state(), state2, proof)
        except InvalidProof:
            continue

        assert proof.retrieve_prior_state() in genuine


@pytest.mark.default_config
def test_consistency_right_subtree_forgery(tree, size1):
    from pymerkle import ConsistencyProof

    size2 = tree.get_size()
    if size2 < 2:
        return

    k = 1 << log2(size2)
    if k == size2:
        k >>= 1
    lnode, rnode = tree._get_root(0, k), tree._get_root(k, size2)

    proof = ConsistencyProof(tree.algorithm, tree.security, size2, size1,
            [1, 0], [1, 0], [rnode, lnode])
    with pytest.raises(InvalidProof):
        verify_consistency(rnode, tree.get_state(), proof)


@pytest.mark.default_config
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


@pytest.mark.default_config
def test_consistency_tampered_prior_size(tree, size1):
    size2 = tree.get_size()
    proof = tree.prove_consistency(size1, size2)
    state1 = tree.get_state(size1)
    state2 = tree.get_state(size2)

    for prior_size in (None, 0, size2 + 1, '1'):
        proof.prior_size = prior_size
        with pytest.raises(InvalidProof):
            verify_consistency(state1, state2, proof)


@pytest.mark.default_config
def test_consistency_serialization(tree, size1):
    from pymerkle import MerkleProof

    size2 = tree.get_size()
    proof = MerkleProof.deserialize(
        tree.prove_consistency(size1, size2).serialize())

    assert proof.prior_size == size1
    verify_consistency(tree.get_state(size1), tree.get_state(size2), proof)


def test_consistency_layout(tree, size1):
    from pymerkle.core import consistency_layout

    for size2 in range(size1, tree.get_size() + 1):
        rule, subset, path = tree._consistency_path_naive(size1, size2)
        layout_rule, layout_subset, ranges = consistency_layout(size1, size2)

        assert (layout_rule, layout_subset) == (rule, subset)
        assert [tree._get_root_naive(*r) for r in ranges] == path


def test_consistency_security_downgrade():
    """
    With prefixes disabled by the prover and path elements of arbitrary
    length, the interior node preimage 0x01 || lnode used to be accepted as
    prior state of a secure tree.
    """
    from pymerkle import InmemoryTree, ConsistencyProof

    tree = InmemoryTree.init_from_entries([b'a', b'b'])
    lnode, rnode = tree.get_leaf(1), tree.get_leaf(2)
    forged = b'\x01' + lnode

    proof = ConsistencyProof('sha256', False, 2, 1, [1, 0], [0, 1],
            [rnode, forged])
    assert proof.retrieve_prior_state() == forged
    assert proof.resolve() == tree.get_state()

    with pytest.raises(InvalidProof):
        verify_consistency(forged, tree.get_state(), proof)

    with pytest.raises(InvalidProof):
        verify_consistency(forged, tree.get_state(), proof, security=False)


@pytest.mark.default_config
def test_consistency_expected_algorithm(tree, size1):
    size2 = tree.get_size()
    proof = tree.prove_consistency(size1, size2)
    state1 = tree.get_state(size1)
    state2 = tree.get_state(size2)

    verify_consistency(state1, state2, proof, algorithm=tree.algorithm)

    other = 'sha512' if tree.algorithm != 'sha512' else 'sha256'
    with pytest.raises(InvalidProof):
        verify_consistency(state1, state2, proof, algorithm=other)


def test_consistency_huge_size():
    from pymerkle import InmemoryTree

    tree = InmemoryTree.init_from_entries([b'a', b'b', b'c'])
    proof = tree.prove_consistency(2)
    proof.size = 10 ** 100000

    with pytest.raises(InvalidProof):
        verify_consistency(tree.get_state(2), tree.get_state(), proof)


@pytest.mark.default_config
def test_consistency_proof_type(tree, size1):
    from pymerkle import MerkleProof, InclusionProof, ConsistencyProof

    proof = tree.prove_consistency(size1)
    data = proof.serialize()

    assert data['type'] == 'consistency'
    assert isinstance(MerkleProof.deserialize(data), ConsistencyProof)
    assert isinstance(ConsistencyProof.deserialize(data), ConsistencyProof)

    with pytest.raises(InvalidProof):
        InclusionProof.deserialize(data)

    with pytest.raises(InvalidProof):
        verify_inclusion(tree.get_leaf(1), tree.get_state(), proof)
