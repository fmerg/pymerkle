import pytest
from pymerkle import MerkleTree, InvalidChallenge, InvalidProof
from tests.conftest import option, all_configs


maxlength = 4
trees = []
trees_and_subtrees = []
for config in all_configs(option):
    for length in range(1, maxlength + 1):
        entries = ['%d-th entry' % _ for _ in range(length)]

        tree = MerkleTree.init_from_entries(*entries, config=config)
        trees += [tree]

        for sublength in range(1, tree.length + 1):
            subtree = MerkleTree.init_from_entries(
                *entries[:sublength], config=config
            )
            trees_and_subtrees += [(tree, subtree)]


@pytest.mark.parametrize('tree', trees)
def test_invalid_challenge(tree):
    with pytest.raises(InvalidChallenge):
        tree.prove_consistency(b'something random')


@pytest.mark.parametrize('tree, subtree', trees_and_subtrees)
def test_invalid_proof(tree, subtree):
    challenge = subtree.get_root_hash()
    proof = tree.prove_consistency(challenge)
    with pytest.raises(InvalidProof):
        proof.verify(target=b'something random')


@pytest.mark.parametrize('tree, subtree', trees_and_subtrees)
def test_success(tree, subtree):
    challenge = subtree.get_root_hash()
    proof = tree.prove_consistency(challenge)
    valid = proof.verify(target=tree.get_root_hash())
    assert valid
