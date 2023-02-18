import pytest
import os
import json
from pymerkle import MerkleTree
from pymerkle.hashing import HashEngine
from tests.conftest import option, all_configs


@pytest.mark.parametrize('config', all_configs(option))
def test_append_entry(config):
    tree = MerkleTree(**config)

    data = 'data'
    tree.append_entry(data)
    assert tree.get_tail().value == tree.hash_entry(data)

    data = 'data'.encode(tree.encoding)
    tree.append_entry(data)
    assert tree.get_tail().value == tree.hash_entry(data)


@pytest.mark.parametrize('config', all_configs(option))
def test_previous_state_edge_cases(config):
    tree = MerkleTree(**config)
    assert not tree.has_previous_state(b'anything')

    tree.append_entry('a')
    state = tree.get_root_hash()
    assert tree.has_previous_state(state)


@pytest.mark.parametrize('config', all_configs(option))
def test_previous_state_success(config):
    tree = MerkleTree.init_from_entries(
        'a', 'b', 'c', 'd', 'e', config=config
    )

    state = tree.get_root_hash()
    for data in ('f', 'g', 'h', 'k'):
        tree.append_entry(data)
        assert tree.has_previous_state(state)


@pytest.mark.parametrize('config', all_configs(option))
def test_previous_state_failure(config):
    tree = MerkleTree.init_from_entries(
        'a', 'b', 'c', 'd', 'e', config=config
    )

    state = b'non_existent_state'
    for data in ('f', 'g', 'h', 'k'):
        tree.append_entry(data)
        assert not tree.has_previous_state(state)
