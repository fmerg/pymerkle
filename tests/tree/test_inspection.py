import pytest
import os
import json

from pymerkle import MerkleTree
from pymerkle.tree import TREE_TEMPLATE


def test___repr__non_default_empty_tree():
    tree = MerkleTree(hash_type='sha512', encoding='UTF-32', security=False)
    assert tree.__repr__() == TREE_TEMPLATE.format(uuid=tree.uuid,
                                                   hash_type='SHA512',
                                                   encoding='UTF-32',
                                                   security='DEACTIVATED',
                                                   root_hash='[None]',
                                                   length=0,
                                                   size=0,
                                                   height=0)


def test___repr__default_non_empty_tree():
    tree = MerkleTree.init_from_records(b'first', b'second', b'third')
    assert tree.__repr__() == TREE_TEMPLATE.format(uuid=tree.uuid,
                                                   hash_type='SHA256',
                                                   encoding='UTF-8',
                                                   security='ACTIVATED',
                                                   root_hash=tree.root_hash.decode(
                                                       tree.encoding),
                                                   length=3,
                                                   size=5,
                                                   height=2)


empty_tree = MerkleTree.init_from_records()
one_leaf_tree = MerkleTree.init_from_records('first')
three_leaves_tree = MerkleTree.init_from_records('first', 'second', 'third')

serializations = [
    (
        empty_tree,
        {
            "encoding": "utf_8",
            "hash_type": "sha256",
            "security": True,
            "hashes": [],
        }
    ),
    (
        one_leaf_tree,
        {
            "encoding": "utf_8",
            "hash_type": "sha256",
            "security": True,
            "hashes": [
                "a1af030231ca2fd20ecf30c5294baf8f69321d09bb16ac53885ccd17a385280d"
            ],
        }
    ),
    (
        three_leaves_tree,
        {
            "encoding": "utf_8",
            "hash_type": "sha256",
            "security": True,
            "hashes": [
                "a1af030231ca2fd20ecf30c5294baf8f69321d09bb16ac53885ccd17a385280d",
                "a94dd4d3c2c6d2548ca4e560d72727bab5d795500191f5b85579130dd3b14603",
                "656d3e8f544238cdf6e32d640f51ba0914959b14edd7a52d0b8b99ab4c8ac6c6"
            ],
        }
    )
]


@pytest.mark.parametrize('tree, serialized', serializations)
def test_serialization(tree, serialized):
    assert tree.serialize() == serialized

@pytest.mark.parametrize('tree, serialized', serializations)
def test_tree_toJSONText(tree, serialized):
    assert tree.toJSONText() == json.dumps(serialized, indent=4, sort_keys=True)


stringifications = [
    (
        empty_tree,
        '\n └─[None]\n'
    ),
    (
        one_leaf_tree,
        '\n └─a1af030231ca2fd20ecf30c5294baf8f69321d09bb16ac53885ccd17a385280d\n'
    ),
    (
        three_leaves_tree,
        '\n └─2427940ec5c9197add5f33423ba3971c3524f4b78f349ee45094b52d0d550fea\n\
     ├──a84762b529735022ce1d7bdc3f24e94aba96ad8b3f6e4866bca76899da094df3\n\
     │    ├──a1af030231ca2fd20ecf30c5294baf8f69321d09bb16ac53885ccd17a385280d\n\
     │    └──a94dd4d3c2c6d2548ca4e560d72727bab5d795500191f5b85579130dd3b14603\n\
     └──656d3e8f544238cdf6e32d640f51ba0914959b14edd7a52d0b8b99ab4c8ac6c6\n'
    )
]


@pytest.mark.parametrize('tree, stringified', stringifications)
def test___str__(tree, stringified):
    assert tree.__str__() == stringified
