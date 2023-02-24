import pytest
from pymerkle import MerkleTree, InvalidChallenge, InvalidProof
from pymerkle.proof import verify_consistency
from tests.conftest import option, all_configs


maxlength = 4
trees = []
trees_and_subtrees = []
for config in all_configs(option):
    for length in range(1, maxlength + 1):
        entries = ['%d-th entry' % _ for _ in range(length)]

        tree = MerkleTree.init_from_entries(*entries, **config)
        trees += [tree]

        for sublength in range(1, tree.length + 1):
            subtree = MerkleTree.init_from_entries(
                *entries[:sublength], **config
            )
            trees_and_subtrees += [(tree, subtree)]


@pytest.mark.parametrize('tree, subtree', trees_and_subtrees)
def test_invalid_challenge(tree, subtree):
    with pytest.raises(InvalidChallenge):
        tree.prove_consistency(subtree.length + 1, subtree.root)

    with pytest.raises(InvalidChallenge):
        tree.prove_consistency(subtree.length, b'random')


@pytest.mark.parametrize('tree, subtree', trees_and_subtrees)
def test_invalid_state(tree, subtree):
    proof = tree.prove_consistency(subtree.length, subtree.root)

    with pytest.raises(InvalidProof):
        verify_consistency(proof, b'random', tree.root)


@pytest.mark.parametrize('tree, subtree', trees_and_subtrees)
def test_invalid_target(tree, subtree):
    proof = tree.prove_consistency(subtree.length, subtree.root)

    with pytest.raises(InvalidProof):
        verify_consistency(proof, subtree.root, b'random')


@pytest.mark.parametrize('tree, subtree', trees_and_subtrees)
def test_success(tree, subtree):
    proof = tree.prove_consistency(subtree.length, subtree.root)

    verify_consistency(proof, subtree.root, tree.root)
