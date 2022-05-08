import pytest
import os
import json

from pymerkle.core import MerkleTree
from pymerkle.core.tree import TREE_TEMPLATE


def test___repr__non_default_empty_tree():
    tree = MerkleTree(hash_type='sha512', encoding='UTF-32', security=False)
    assert tree.__repr__() == TREE_TEMPLATE.format(uuid=tree.uuid,
                                                   hash_type='SHA512',
                                                   encoding='UTF-32',
                                                   raw_bytes='TRUE',
                                                   security='DEACTIVATED',
                                                   root_hash='[None]',
                                                   length=0,
                                                   size=0,
                                                   height=0)


def test___repr__default_non_empty_tree():
    tree = MerkleTree(b'first', b'second', b'third')
    assert tree.__repr__() == TREE_TEMPLATE.format(uuid=tree.uuid,
                                                   hash_type='SHA256',
                                                   encoding='UTF-8',
                                                   raw_bytes='TRUE',
                                                   security='ACTIVATED',
                                                   root_hash=tree.root_hash.decode(
                                                       tree.encoding),
                                                   length=3,
                                                   size=5,
                                                   height=2)


empty_tree = MerkleTree()
one_leaf_tree = MerkleTree('first')
three_leaves_tree = MerkleTree('first', 'second', 'third')

serializations = [
    (
        empty_tree,
        {
            "hashes": [],
            "header": {
                "encoding": "utf_8",
                "hash_type": "sha256",
                "raw_bytes": True,
                "security": True
            }
        }
    ),
    (
        one_leaf_tree,
        {
            "hashes": [
                "a1af030231ca2fd20ecf30c5294baf8f69321d09bb16ac53885ccd17a385280d"
            ],
            "header": {
                "encoding": "utf_8",
                "hash_type": "sha256",
                "raw_bytes": True,
                "security": True
            }
        }
    ),
    (
        three_leaves_tree,
        {
            "hashes": [
                "a1af030231ca2fd20ecf30c5294baf8f69321d09bb16ac53885ccd17a385280d",
                "a94dd4d3c2c6d2548ca4e560d72727bab5d795500191f5b85579130dd3b14603",
                "656d3e8f544238cdf6e32d640f51ba0914959b14edd7a52d0b8b99ab4c8ac6c6"
            ],
            "header": {
                "encoding": "utf_8",
                "hash_type": "sha256",
                "raw_bytes": True,
                "security": True
            }
        }
    )
]


@pytest.mark.parametrize('tree, serialization', serializations)
def test_serialization(tree, serialization):
    assert tree.serialize() == serialization


stringifications = [
    (
        empty_tree,
        '\n └─[None]'
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


@pytest.mark.parametrize('tree, stringification', stringifications)
def test___str__(tree, stringification):
    assert tree.__str__() == stringification


json_texts = [
    (
        empty_tree,
        '{\n    "hashes": [],\n    "header": {\n        "encoding": "utf_8",' +
        '\n        "hash_type": "sha256",\n        "raw_bytes": true,' +
        '\n        "security": true\n    }\n}'
    ),
    (
        one_leaf_tree,
        '{\n    "hashes": [\n        ' +
        '"a1af030231ca2fd20ecf30c5294baf8f69321d09bb16ac53885ccd17a385280d"\n' +
        '    ],\n    "header": {\n        "encoding": "utf_8",\n        ' +
        '"hash_type": "sha256",\n        "raw_bytes": true,\n        ' +
        '"security": true\n    }\n}'
    ),
    (
        three_leaves_tree,
        '{\n    "hashes": [\n        ' +
        '"a1af030231ca2fd20ecf30c5294baf8f69321d09bb16ac53885ccd17a385280d",\n' +
        '        "a94dd4d3c2c6d2548ca4e560d72727bab5d795500191f5b85579130dd3b14603",' +
        '\n        "656d3e8f544238cdf6e32d640f51ba0914959b14edd7a52d0b8b99ab4c8ac6c6"' +
        '\n    ],\n    "header": {\n        "encoding": "utf_8",\n        ' +
        '"hash_type": "sha256",\n        "raw_bytes": true,\n        ' +
        '"security": true\n    }\n}'
    )
]


@pytest.mark.parametrize('tree, json_text', json_texts)
def test_tree_toJSONtext(tree, json_text):
    assert tree.toJSONtext() == json_text
