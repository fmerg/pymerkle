import pytest
import os
import json
from pymerkle import MerkleTree
from pymerkle.hashing import HashEngine
from tests.conftest import option, all_configs


@pytest.mark.parametrize('config', all_configs(option))
def test_append_entry(config):
    tree = MerkleTree(**config)
    engine = HashEngine(**config)

    data = 'data'
    tree.append_entry(data)
    assert tree.get_tail().value == engine.hash_entry(data)

    data = 'data'.encode(tree.encoding)
    tree.append_entry(data)
    assert tree.get_tail().value == engine.hash_entry(data)
