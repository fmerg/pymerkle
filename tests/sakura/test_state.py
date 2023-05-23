import pytest
from pymerkle import MerkleTree
from pymerkle.tree import InvalidChallenge
from pymerkle.proof import verify_inclusion, verify_consistency, InvalidProof
from tests.conftest import option, all_configs


tree_subsize = []

maxsize = 11
for config in all_configs(option):
    for size in range(0, maxsize + 1):
        entries = ['%d-th entry' % _ for _ in range(size)]
        tree = MerkleTree.init_from_entries(*entries, **config)

        for subsize in range(0, size + 1):
            tree_subsize += [(tree, subsize)]


@pytest.mark.parametrize('tree, subsize', tree_subsize)
def test_state(tree, subsize):
    assert tree.get_state(subsize) == tree.hash_range(0, subsize)
