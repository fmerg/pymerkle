import pytest
from pymerkle.tree import MerkleTree
from pymerkle.hashing import UnsupportedParameter
from tests.conftest import option, all_configs


def test_append():
    tree = MerkleTree()

    assert not tree and not tree.root
    assert (tree.length, tree.size, tree.height) == (0, 0, 0)

    checksum = tree.append_entry('a')
    assert checksum == tree.hash_entry('a')
    assert (tree.length, tree.size, tree.height) == (1, 1, 0)

    checksum = tree.append_entry('b')
    assert checksum == tree.hash_entry('b')
    assert (tree.length, tree.size, tree.height) == (2, 3, 1)

    checksum = tree.append_entry('c')
    assert checksum == tree.hash_entry('c')
    assert (tree.length, tree.size, tree.height) == (3, 5, 2)

    assert tree and tree.root


@pytest.mark.parametrize('config', all_configs(option))
def test_metadata(config):
    assert MerkleTree(**config).get_metadata() == {key: value.replace('-', '_')
            if isinstance(value, str) else value for (key, value) in
            config.items()}


def test_unsupported():
    with pytest.raises(UnsupportedParameter):
        MerkleTree(algorithm='anything_unsupported')

    with pytest.raises(UnsupportedParameter):
        MerkleTree(encoding='anything_unsupported')
