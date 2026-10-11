import pytest

from pymerkle import verify_inclusion, verify_consistency, InvalidChallenge, \
    InvalidProof, MerkleProof, InclusionProof, ConsistencyProof, \
    InmemoryTree
from pymerkle.core import inclusion_layout


def prove(tree, index):
    """
    Returns the hash of the provided leaf, the current state and the proof of
    inclusion of the former in the latter.
    """
    return tree.get_leaf(index), tree.get_state(), tree.prove_inclusion(index)


def test_inclusion_success(tree, index):
    base, state, proof = prove(tree, index)

    verify_inclusion(base, state, proof, security=tree.security)


@pytest.mark.default_config
def test_inclusion_invalid_base(tree, index):
    _, state, proof = prove(tree, index)
    base = tree.hash_raw(b'random')

    with pytest.raises(InvalidProof):
        verify_inclusion(base, state, proof)


@pytest.mark.default_config
def test_inclusion_invalid_state(tree, index):
    base, _, proof = prove(tree, index)
    state = tree.hash_raw(b'random')

    with pytest.raises(InvalidProof):
        verify_inclusion(base, state, proof)


@pytest.mark.default_config
def test_inclusion_invalid_challenge(tree, index):
    size = tree.get_size()

    with pytest.raises(InvalidChallenge):
        tree.prove_inclusion(index, size + 1)

    with pytest.raises(InvalidChallenge):
        tree.prove_inclusion(0, size)

    with pytest.raises(InvalidChallenge):
        tree.prove_inclusion(-1, size)

    with pytest.raises(InvalidChallenge):
        tree.prove_inclusion(index + 1, index)


@pytest.mark.default_config
def test_inclusion_wrong_type(tree, index):
    base, state, proof = prove(tree, index)

    with pytest.raises(InvalidProof):
        verify_inclusion(base.hex(), state, proof)

    with pytest.raises(InvalidProof):
        verify_inclusion(base, state.hex(), proof)


@pytest.mark.default_config
def test_inclusion_empty_path(tree, index):
    base = tree.get_leaf(index)
    state = tree.get_state()
    proof = InclusionProof(tree.algorithm, tree.security, tree.get_size(),
        index, [], [])

    with pytest.raises(InvalidProof):
        verify_inclusion(base, state, proof)


@pytest.mark.default_config
def test_inclusion_expected_index_and_size(tree, index):
    size = tree.get_size()
    base, state, proof = prove(tree, index)

    verify_inclusion(base, state, proof, index=index, size=size)

    with pytest.raises(InvalidProof):
        verify_inclusion(base, state, proof, index=index % size + 1
            if size > 1 else 2)

    with pytest.raises(InvalidProof):
        verify_inclusion(base, state, proof, size=size + 1)


@pytest.mark.default_config
def test_inclusion_tampered_index(tree, index):
    """
    The proof used not to commit to the leaf position; a valid proof must now
    fail if the claimed index is changed.
    """
    size = tree.get_size()
    base = tree.get_leaf(index)
    state = tree.get_state()

    for claimed in [i for i in range(1, size + 1) if i != index] + \
            [None, 0, size + 1, '1']:
        proof = tree.prove_inclusion(index)
        proof.index = claimed
        with pytest.raises(InvalidProof):
            verify_inclusion(base, state, proof)


@pytest.mark.default_config
def test_inclusion_tampered_rule(tree, index):
    base = tree.get_leaf(index)
    state = tree.get_state()

    for i in range(len(tree.prove_inclusion(index).rule)):
        proof = tree.prove_inclusion(index)
        proof.rule[i] ^= 1
        with pytest.raises(InvalidProof):
            verify_inclusion(base, state, proof)


@pytest.mark.default_config
def test_inclusion_serialization(tree, index):
    proof = MerkleProof.deserialize(tree.prove_inclusion(index).serialize())

    assert proof.index == index
    verify_inclusion(tree.get_leaf(index), tree.get_state(), proof)


def test_inclusion_layout(tree, index):
    for size in range(index, tree.get_size() + 1):
        rule, path = tree._inclusion_path_naive(index, size)
        layout_rule, ranges = inclusion_layout(index, size)

        assert layout_rule == rule
        assert [tree._get_root_naive(*r) for r in ranges] == path


@pytest.mark.default_config
def test_inclusion_security_downgrade(tree, index):
    base, state, proof = prove(tree, index)
    proof.security = False
    with pytest.raises(InvalidProof):
        verify_inclusion(base, state, proof)


@pytest.mark.default_config
def test_inclusion_expected_algorithm(tree, index):
    base, state, proof = prove(tree, index)

    variant = tree.algorithm.upper().replace('_', '-')
    verify_inclusion(base, state, proof, algorithm=variant)

    other = 'sha512' if tree.algorithm != 'sha512' else 'sha256'
    with pytest.raises(InvalidProof):
        verify_inclusion(base, state, proof, algorithm=other)


@pytest.mark.default_config
def test_inclusion_invalid_digest_length(tree, index):
    base = tree.get_leaf(index)
    state = tree.get_state()

    for i in range(len(tree.prove_inclusion(index).path)):
        for alter in (lambda d: d[:-1], lambda d: d + b'\x00', bytes.hex):
            proof = tree.prove_inclusion(index)
            proof.path[i] = alter(proof.path[i])
            with pytest.raises(InvalidProof):
                verify_inclusion(base, state, proof)


@pytest.mark.parametrize('mutate', [
    lambda d: d.pop('metadata'),
    lambda d: d.pop('path'),
    lambda d: d['metadata'].update({'extra': 1}),
    lambda d: d['metadata'].update({'algorithm': 'md5'}),
    lambda d: d['metadata'].pop('algorithm'),
    lambda d: d.update({'path': ['zz']}),
    lambda d: d.update({'path': [1]}),
    lambda d: d.update({'path': None}),
    lambda d: d.update({'path': ['00'] * 1000}),
    lambda d: d.pop('type'),
    lambda d: d.update({'type': 'unknown'}),
    lambda d: d.update({'type': 'consistency'}),
])
def test_deserialize_malformed(mutate):
    tree = InmemoryTree.init_from_entries([b'a', b'b', b'c'])
    data = tree.prove_inclusion(2).serialize()
    mutate(data)

    with pytest.raises(InvalidProof):
        MerkleProof.deserialize(data)


def test_inclusion_invalid_rule_bit():
    tree = InmemoryTree.init_from_entries([b'a', b'b', b'c'])
    data = tree.prove_inclusion(2).serialize()
    data['rule'][0] = 2

    with pytest.raises(InvalidProof):
        verify_inclusion(tree.get_leaf(2), tree.get_state(),
            MerkleProof.deserialize(data))


def test_inclusion_huge_size():
    tree = InmemoryTree.init_from_entries([b'a', b'b', b'c'])
    proof = tree.prove_inclusion(2)
    proof.size = 10 ** 100000

    with pytest.raises(InvalidProof):
        verify_inclusion(tree.get_leaf(2), tree.get_state(), proof)


@pytest.mark.default_config
def test_inclusion_proof_type(tree, index):
    proof = tree.prove_inclusion(index)
    data = proof.serialize()

    assert data['type'] == 'inclusion'
    assert 'subset' not in data
    assert isinstance(MerkleProof.deserialize(data), InclusionProof)
    assert isinstance(InclusionProof.deserialize(data), InclusionProof)

    with pytest.raises(InvalidProof):
        ConsistencyProof.deserialize(data)

    with pytest.raises(InvalidProof):
        verify_consistency(tree.get_state(), tree.get_state(), proof)
