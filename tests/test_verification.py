import pytest
from pymerkle import MerkleTree
from pymerkle.tree import InvalidChallenge
from pymerkle.proof import verify_inclusion, verify_consistency, InvalidProof
from tests.conftest import option, all_configs


maxsize = 4
trees = []
trees_and_indexes = []
trees_and_subtrees = []
for config in all_configs(option):
    for size in range(1, maxsize + 1):
        entries = ['%d-th entry' % _ for _ in range(size)]

        tree = MerkleTree.init_from_entries(*entries, **config)
        trees += [tree]

        for (offset, _) in enumerate(entries):
            trees_and_indexes += [(tree, offset + 1)]

        for subsize in range(1, tree.get_size() + 1):
            subtree = MerkleTree.init_from_entries(
                *entries[:subsize], **config
            )
            trees_and_subtrees += [(tree, subtree)]


@pytest.mark.parametrize('tree', trees)
def test_inclusion_invalid_challenge(tree):
    size = tree.get_size() + 1

    with pytest.raises(InvalidChallenge):
        tree.prove_inclusion(size + 1)

    with pytest.raises(InvalidChallenge):
        tree.prove_inclusion(1, size + 1)


@pytest.mark.parametrize('tree, index', trees_and_indexes)
def test_inclusion_invalid_base(tree, index):
    proof = tree.prove_inclusion(index)

    with pytest.raises(InvalidProof):
        verify_inclusion(b'random', tree.get_state(), proof)


@pytest.mark.parametrize('tree, index', trees_and_indexes)
def test_inclusion_invalid_target(tree, index):
    proof = tree.prove_inclusion(index)
    base = tree.get_leaf(index)
    with pytest.raises(InvalidProof):
        verify_inclusion(base, b'random', proof)


@pytest.mark.parametrize('tree, index', trees_and_indexes)
def test_inclusion_success(tree, index):
    proof = tree.prove_inclusion(index)
    base = tree.get_leaf(index)
    verify_inclusion(base, tree.get_state(), proof)


@pytest.mark.parametrize('tree, subtree', trees_and_subtrees)
def test_consistency_invalid_challenge(tree, subtree):
    with pytest.raises(InvalidChallenge):
        tree.prove_consistency(subtree.get_size() + 1, subtree.get_state())

    with pytest.raises(InvalidChallenge):
        tree.prove_consistency(subtree.get_size(), b'random')


@pytest.mark.parametrize('tree, subtree', trees_and_subtrees)
def test_consistency_invalid_state(tree, subtree):
    proof = tree.prove_consistency(subtree.get_size(), subtree.get_state())

    with pytest.raises(InvalidProof):
        verify_consistency(b'random', tree.get_state(), proof)


@pytest.mark.parametrize('tree, subtree', trees_and_subtrees)
def test_consistency_invalid_target(tree, subtree):
    proof = tree.prove_consistency(subtree.get_size(), subtree.get_state())

    with pytest.raises(InvalidProof):
        verify_consistency(subtree.get_state(), b'random', proof)


@pytest.mark.parametrize('tree, subtree', trees_and_subtrees)
def test_consistency_success(tree, subtree):
    proof = tree.prove_consistency(subtree.get_size(), subtree.get_state())

    verify_consistency(subtree.get_state(), tree.get_state(), proof)
