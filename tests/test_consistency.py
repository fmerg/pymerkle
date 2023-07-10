import pytest
from tests.conftest import tree_and_index

from pymerkle import verify_inclusion, verify_consistency, InvalidChallenge, \
    InvalidProof


@pytest.mark.parametrize('tree, lsize', tree_and_index())
def test_consistency_success(tree, lsize):
    rsize = tree.get_size()
    proof = tree.prove_consistency(lsize, rsize)

    state1 = tree.get_state(lsize)
    state2 = tree.get_state()

    verify_consistency(state1, state2, proof)


@pytest.mark.parametrize('tree, lsize', tree_and_index(default_config=True))
def test_consistency_invalid_prior(tree, lsize):
    rsize = tree.get_size()
    proof = tree.prove_consistency(lsize, rsize)

    state1 = tree.hash_raw(b'random')
    state2 = tree.get_state(rsize)
    with pytest.raises(InvalidProof):
        verify_consistency(state1, state2, proof)


@pytest.mark.parametrize('tree, lsize', tree_and_index(default_config=True))
def test_consistency_invalid_state(tree, lsize):
    rsize = tree.get_size()
    proof = tree.prove_consistency(lsize, rsize)

    state1 = tree.get_state(lsize)
    state2 = tree.hash_raw(b'random')
    with pytest.raises(InvalidProof):
        verify_consistency(state1, state2, proof)


@pytest.mark.parametrize('tree, lsize', tree_and_index(default_config=True))
def test_consistency_invalid_challenge(tree, lsize):
    rsize = tree.get_size()

    with pytest.raises(InvalidChallenge):
        tree.prove_consistency(lsize, rsize + 1)

    with pytest.raises(InvalidChallenge):
        tree.prove_consistency(lsize, -1)

    with pytest.raises(InvalidChallenge):
        tree.prove_consistency(lsize + 1, lsize)

    with pytest.raises(InvalidChallenge):
        tree.prove_consistency(-1, lsize)
