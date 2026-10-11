import pytest
from tests.conftest import tree_and_index

from pymerkle import verify_inclusion, verify_consistency, InvalidChallenge, \
    InvalidProof, MerkleProof


@pytest.mark.parametrize('tree, index', tree_and_index())
def test_inclusion_success(tree, index):
    base = tree.get_leaf(index)
    proof = tree.prove_inclusion(index)
    state = tree.get_state()

    verify_inclusion(base, state, proof)


@pytest.mark.parametrize('tree, index', tree_and_index(default_config=True))
def test_inclusion_invalid_base(tree, index):
    base = tree.hash_raw(b'random')
    proof = tree.prove_inclusion(index)
    state = tree.get_state()

    with pytest.raises(InvalidProof):
        verify_inclusion(base, state, proof)


@pytest.mark.parametrize('tree, index', tree_and_index(default_config=True))
def test_inclusion_invalid_state(tree, index):
    base = tree.get_leaf(index)
    proof = tree.prove_inclusion(index)
    state = tree.hash_raw(b'random')

    with pytest.raises(InvalidProof):
        verify_inclusion(base, state, proof)


@pytest.mark.parametrize('tree, index', tree_and_index(default_config=True))
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


@pytest.mark.parametrize('tree, index', tree_and_index(default_config=True))
def test_inclusion_wrong_type(tree, index):
    base = tree.get_leaf(index)
    proof = tree.prove_inclusion(index)
    state = tree.get_state()

    with pytest.raises(InvalidProof):
        verify_inclusion(base.hex(), state, proof)

    with pytest.raises(InvalidProof):
        verify_inclusion(base, state.hex(), proof)


@pytest.mark.parametrize('tree, index', tree_and_index(default_config=True))
def test_inclusion_empty_path(tree, index):
    base = tree.get_leaf(index)
    state = tree.get_state()
    proof = MerkleProof.deserialize({
        'metadata': {'algorithm': tree.algorithm, 'security': tree.security,
                     'size': tree.get_size()},
        'rule': [], 'subset': [], 'path': []})

    with pytest.raises(InvalidProof):
        verify_inclusion(base, state, proof)


@pytest.mark.parametrize('tree, index', tree_and_index(default_config=True))
def test_inclusion_expected_index_and_size(tree, index):
    size = tree.get_size()
    base = tree.get_leaf(index)
    proof = tree.prove_inclusion(index)
    state = tree.get_state()

    verify_inclusion(base, state, proof, index=index, size=size)

    with pytest.raises(InvalidProof):
        verify_inclusion(base, state, proof, index=index % size + 1
            if size > 1 else 2)

    with pytest.raises(InvalidProof):
        verify_inclusion(base, state, proof, size=size + 1)


@pytest.mark.parametrize('tree, index', tree_and_index(default_config=True))
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


@pytest.mark.parametrize('tree, index', tree_and_index(default_config=True))
def test_inclusion_tampered_rule(tree, index):
    base = tree.get_leaf(index)
    state = tree.get_state()

    for i in range(len(tree.prove_inclusion(index).rule)):
        proof = tree.prove_inclusion(index)
        proof.rule[i] ^= 1
        with pytest.raises(InvalidProof):
            verify_inclusion(base, state, proof)


@pytest.mark.parametrize('tree, index', tree_and_index(default_config=True))
def test_inclusion_serialization(tree, index):
    proof = MerkleProof.deserialize(tree.prove_inclusion(index).serialize())

    assert proof.index == index
    verify_inclusion(tree.get_leaf(index), tree.get_state(), proof)


@pytest.mark.parametrize('tree, index', tree_and_index())
def test_inclusion_structure(tree, index):
    from pymerkle.proof import _inclusion_structure

    for size in range(index, tree.get_size() + 1):
        proof = tree.prove_inclusion(index, size)
        assert _inclusion_structure(index - 1, size) == proof.rule
