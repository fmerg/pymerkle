import pytest
from pymerkle import MerkleTree, InvalidChallenge, InvalidProof
from pymerkle.proof import verify_inclusion
from tests.conftest import option, all_configs


maxlength = 4
trees = []
trees_and_entries = []
for config in all_configs(option):
    for length in range(1, maxlength + 1):
        entries = ['%d-entry' % _ for _ in range(length)]

        tree = MerkleTree.init_from_entries(*entries, **config)
        trees += [tree]

        for data in entries:
            trees_and_entries += [(tree, data)]


@pytest.mark.parametrize('tree', trees)
def test_invalid_challenge(tree):
    with pytest.raises(InvalidChallenge):
        tree.prove_inclusion(b'random')


@pytest.mark.parametrize('tree, data', trees_and_entries)
def test_invalid_base(tree, data):
    proof = tree.prove_inclusion(data)
    target = tree.get_root()

    with pytest.raises(InvalidProof):
        verify_inclusion(proof, b'random', target)


@pytest.mark.parametrize('tree, data', trees_and_entries)
def test_invalid_target(tree, data):
    proof = tree.prove_inclusion(data)

    with pytest.raises(InvalidProof):
        verify_inclusion(proof, data, b'random')


@pytest.mark.parametrize('tree, data', trees_and_entries)
def test_success(tree, data):
    proof = tree.prove_inclusion(data)
    target = tree.get_root()

    verify_inclusion(proof, data, target)
