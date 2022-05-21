import pytest
import os
import json
import glob

from pymerkle import MerkleTree


# Clean exports dir before running tests
exports_dir = os.path.join(os.path.dirname(__file__), 'exports')
for f in glob.glob(os.path.join(exports_dir, '*')):
    os.remove(f)


def test_export():
    tree = MerkleTree.init_from_records(*['%d-th record' % i for i in range(12)])
    export_path = os.path.join(exports_dir, '%s.json' % tree.uuid)
    tree.export(filepath=export_path)

    with open(export_path, 'rb') as f:
        exported = json.load(f)

    assert exported == {
        "encoding": "utf_8",
        "hash_type": "sha256",
        "security": True,
        "hashes": [
            "a08665f5138f40a07987234ec9821e5be05ecbf5d7792cd4155c4222618029b6",
            "3dbbc4898d7e909de7fc7bb1c0af36feba78abc802102556e4ea52c28ccb517f",
            "45c44059cf0f5a447933f57d851a6024ac78b44a41603738f563bcbf83f35d20",
            "b5db666b0b34e92c2e6c1d55ba83e98ff37d6a98dda532b125f049b43d67f802",
            "69df93cbafa946cfb27c4c65ae85222ad5c7659237124c813ed7900a7be83e81",
            "9d6761f55a3e87166d2ea6d00db9c88159c893674a8420cb8d32c35dbb791fd4",
            "e718ae6ea64cb37a593654f9c0d7ec81d11498fdd94fc5473b999cd6c00d05c6",
            "ad2c93dd91eafb31ad91deb8c1b318b126957608d13bfdba209a5f17ecf22503",
            "cdc94791cd56543e1b28b21587c76f7cb45203fa7b1b8aa219e6ccc527a0d0d9",
            "828a54ce62ae58e01271a3bde442e0fa6bfa758b2816dd39f873718dfa27634a",
            "5ebc41746c5fbcfd8d32eef74f1aaaf02d6da8ff94426855393732db8b73126a",
            "b70665abe265a88bc68ec625154746457a2ba7ecb5a7fc792e9443f618fc93fd"
        ]
    }


def test_fromJSONFile():
    tree = MerkleTree.init_from_records(*['%d-th record' % i for i in range(12)])
    export_path = os.path.join(exports_dir, '%s.json' % tree.uuid)
    tree.export(filepath=export_path)

    assert tree.serialize() == MerkleTree.fromJSONFile(export_path).serialize()
