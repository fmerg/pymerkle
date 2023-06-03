import pytest
from tests.conftest import tree_and_index

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

    state1 = tree.hash_leaf(b'random').hex()
    state2 = tree.get_state(size2)
    with pytest.raises(InvalidProof):
        verify_consistency(state1, state2, proof)


@pytest.mark.parametrize('tree, size1', tree_and_index(default_config=True))
def test_consistency_invalid_state(tree, size1):
    size2 = tree.get_size()
    proof = tree.prove_consistency(size1, size2)

    state1 = tree.get_state(size1)
    state2 = tree.hash_leaf(b'random').hex()
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
