import pytest
from pymerkle.tree import MerkleTree, UnsupportedParameter
from tests.conftest import option, all_configs


def test_construction_error():
    with pytest.raises(UnsupportedParameter):
        MerkleTree(algorithm='anything_unsupported')

    with pytest.raises(UnsupportedParameter):
        MerkleTree(encoding='anything_unsupported')


def test_bool():
    tree = MerkleTree()
    assert not tree
    assert not tree.get_root_hash()

    tree = MerkleTree.init_from_records('a')
    assert tree
    assert tree.get_root_hash()


def test_dimensions():
    tree = MerkleTree()
    assert (tree.length, tree.size, tree.height) == (0, 0, 0)

    tree = MerkleTree.init_from_records('a', 'b', 'c')
    assert (tree.length, tree.size, tree.height) == (3, 5, 2)


@pytest.mark.parametrize('config', all_configs(option))
def test_previous_state_edge_cases(config):
    tree = MerkleTree(**config)
    assert not tree.has_previous_state(b'anything')

    tree.encrypt('a')
    state = tree.get_root_hash()
    assert tree.has_previous_state(state)


@pytest.mark.parametrize('config', all_configs(option))
def test_previous_state_success(config):
    tree = MerkleTree.init_from_records(
        'a', 'b', 'c', 'd', 'e', config=config
    )

    state = tree.get_root_hash()
    for record in ('f', 'g', 'h', 'k'):
        tree.encrypt(record)
        assert tree.has_previous_state(state)


@pytest.mark.parametrize('config', all_configs(option))
def test_previous_state_failure(config):
    tree = MerkleTree.init_from_records(
        'a', 'b', 'c', 'd', 'e', config=config
    )

    state = b'non_existent_state'
    for record in ('f', 'g', 'h', 'k'):
        tree.encrypt(record)
        assert not tree.has_previous_state(state)
