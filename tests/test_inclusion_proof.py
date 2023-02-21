import pytest
from pymerkle import MerkleTree, InvalidChallenge, InvalidProof
from tests.conftest import option, all_configs


maxlength = 4
trees = []
trees_and_challenges = []
for config in all_configs(option):
    for length in range(1, maxlength + 1):
        entries = ['%d-entry' % _ for _ in range(length)]

        tree = MerkleTree.init_from_entries(*entries, **config)
        trees += [tree]

        for data in entries:
            challenge = tree.hash_entry(data)
            trees_and_challenges += [(tree, challenge)]


@pytest.mark.parametrize('tree', trees)
def test_invalid_challenge(tree):
    with pytest.raises(InvalidChallenge):
        tree.prove_inclusion(b'something random')


@pytest.mark.parametrize('tree, challenge', trees_and_challenges)
def test_invalid_proof(tree, challenge):
    proof = tree.prove_inclusion(challenge)

    with pytest.raises(InvalidProof):
        proof.verify(target=b'something random')


@pytest.mark.parametrize('tree, challenge', trees_and_challenges)
def test_success(tree, challenge):
    proof = tree.prove_inclusion(challenge)

    valid = proof.verify(target=tree.get_root())
    assert valid
