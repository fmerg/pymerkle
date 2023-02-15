import pytest
import os
import json
from pymerkle import MerkleTree
from pymerkle.hashing import HashEngine
from tests.conftest import option, all_configs


trees_engines = []
for config in all_configs(option):
    trees_engines.append(
        (
            MerkleTree(**config),
            HashEngine(**config),
        )
    )


records = []
for tree, engine in trees_engines:
    records.extend(
        [
            (tree, engine, 'record'),
            (tree, engine, 'record'.encode(tree.encoding))
        ]
    )


@pytest.mark.parametrize('tree, engine, record', records)
def test_encrypt(tree, engine, record):
    tree.encrypt(record)
    assert tree.get_tail().value == engine.hash_data(record)
