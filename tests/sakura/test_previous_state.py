import pytest
import os
import json
from pymerkle import MerkleTree
from pymerkle.hashing import HashEngine
from tests.conftest import option, all_configs


@pytest.mark.parametrize('config', all_configs(option))
def test_previous_state_edge_cases(config):
    tree = MerkleTree(**config)
    assert not tree.has_previous_state(b'random')

    tree.append_entry('a')
    assert tree.has_previous_state(tree.get_state())


@pytest.mark.parametrize('config', all_configs(option))
def test_previous_state_success(config):
    tree = MerkleTree.init_from_entries(
        'a', 'b', 'c', 'd', 'e', **config
    )

    substate = tree.get_state()
    for data in ('f', 'g', 'h', 'k'):
        tree.append_entry(data)
        assert tree.has_previous_state(substate)


@pytest.mark.parametrize('config', all_configs(option))
def test_previous_state_failure(config):
    tree = MerkleTree.init_from_entries(
        'a', 'b', 'c', 'd', 'e', **config
    )

    for data in ('f', 'g', 'h', 'k'):
        tree.append_entry(data)
        assert not tree.has_previous_state(b'random')
