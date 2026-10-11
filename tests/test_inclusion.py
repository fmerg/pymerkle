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
