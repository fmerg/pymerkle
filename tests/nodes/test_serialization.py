"""
Tests represenation and serialization of nodes
"""

import pytest

from pymerkle.nodes import Node, Leaf, NODE_TEMPLATE
from pymerkle.hashing import HashEngine


_ = HashEngine()
encoding = _.encoding
hash_func = _.hash

pair_of_leaves = (
    Leaf.from_record(b'some record...', hash_func, encoding),
    Leaf.from_record('5f4e54b52702884b03c21efc76b7433607fa3b35343b9fd322521c9c1ed633b4',
                     hash_func, encoding)
)

# Full binary structure (parent-child relations): 4 leaves, 7 nodes in total
leaf1 = Leaf.from_record(b'first record...', hash_func, encoding)
leaf2 = Leaf.from_record(b'second record...', hash_func, encoding)
leaf3 = Leaf.from_record(b'third record...', hash_func, encoding)
leaf4 = Leaf.from_record(b'fourth record...', hash_func, encoding)
node12 = Node.from_children(leaf1, leaf2, hash_func, encoding)
node34 = Node.from_children(leaf3, leaf4, hash_func, encoding)
root = Node.from_children(node12, node34, hash_func, encoding)


@pytest.mark.parametrize('leaf', (leaf1, leaf2, leaf3, leaf4))
def test___repr__for_leafs_with_parent(leaf):
    assert leaf.__repr__() == NODE_TEMPLATE.format(node=str(hex(id(leaf))),
                                                   left='[None]',
                                                   right='[None]',
                                                   parent=str(hex(id(leaf.parent))),
                                                   checksum=leaf.digest.decode(leaf.encoding))


@pytest.mark.parametrize('node', (node12, node34))
def test___repr__for_nodes_with_parent(node):
    assert node.__repr__() == NODE_TEMPLATE.format(node=str(hex(id(node))),
                                                   left=str(hex(id(node.left))),
                                                   right=str(hex(id(node.right))),
                                                   parent=str(hex(id(node.parent))),
                                                   checksum=node.digest.decode(node.encoding))


def test___repr__for_node_without_parent():
    assert root.__repr__() == NODE_TEMPLATE.format(node=str(hex(id(root))),
                                                   left=str(hex(id(root.left))),
                                                   right=str(hex(id(root.right))),
                                                   parent='[None]',
                                                   checksum=root.digest.decode(root.encoding))


stringifications = [
    (
        leaf1,
        '\n ├──9d6f467ca4962b97397eb9d228ff65a769b378083c7a7cacb50e6817de99bda7\n'
    ),
    (
        leaf2,
        '\n └──9ece01d833058a6603279663a23f08bfbf5f8ba2c4a00dc3581df5d0f599bdaa\n'
    ),
    (
        leaf3,
        '\n ├──ff151d008c290d85c5e4bb53ee099ef975f093e36a8a3363f574bf256c44233f\n'
    ),
    (
        leaf4,
        '\n └──8d8740a5789e9371418549348e4467d62d995bd2f2b9339ef19fcc8467526b69\n'
    ),
    (
        node12,
        '\n ├──cd607f7f417c7f796bc863647558eb068d7f6400683978e32137c688ce128321\n\
     ├──9d6f467ca4962b97397eb9d228ff65a769b378083c7a7cacb50e6817de99bda7\n\
     └──9ece01d833058a6603279663a23f08bfbf5f8ba2c4a00dc3581df5d0f599bdaa\n'
    ),
    (
        node34,
        '\n └──3c4dfc97969d64c2434ed613b1ad931af2dfac935407bf1b7ab2af4b07680b57\n\
     ├──ff151d008c290d85c5e4bb53ee099ef975f093e36a8a3363f574bf256c44233f\n\
     └──8d8740a5789e9371418549348e4467d62d995bd2f2b9339ef19fcc8467526b69\n'
    ),
    (
        root,
        '\n └─d9186bdb6795c3f621ec8b3413f09ed7772b930c4d35da32d49b28d079d36f86\n\
     ├──cd607f7f417c7f796bc863647558eb068d7f6400683978e32137c688ce128321\n\
     │    ├──9d6f467ca4962b97397eb9d228ff65a769b378083c7a7cacb50e6817de99bda7\n\
     │    └──9ece01d833058a6603279663a23f08bfbf5f8ba2c4a00dc3581df5d0f599bdaa\n\
     └──3c4dfc97969d64c2434ed613b1ad931af2dfac935407bf1b7ab2af4b07680b57\n\
          ├──ff151d008c290d85c5e4bb53ee099ef975f093e36a8a3363f574bf256c44233f\n\
          └──8d8740a5789e9371418549348e4467d62d995bd2f2b9339ef19fcc8467526b69\n'
    )
]


@pytest.mark.parametrize("node, stringification", stringifications)
def test___str__(node, stringification):
    assert node.__str__() == stringification


# Serialization tests

serializations = [
    (
        node12,
        {
            'left': {
                'hash': '9d6f467ca4962b97397eb9d228ff65a769b378083c7a7cacb50e6817de99bda7'
            },
            'right': {
                'hash': '9ece01d833058a6603279663a23f08bfbf5f8ba2c4a00dc3581df5d0f599bdaa'
            },
            'hash': 'cd607f7f417c7f796bc863647558eb068d7f6400683978e32137c688ce128321'
        }
    ),
    (
        node34,
        {
            'left': {
                'hash': 'ff151d008c290d85c5e4bb53ee099ef975f093e36a8a3363f574bf256c44233f'
            },
            'right': {
                'hash': '8d8740a5789e9371418549348e4467d62d995bd2f2b9339ef19fcc8467526b69'
            },
            'hash': '3c4dfc97969d64c2434ed613b1ad931af2dfac935407bf1b7ab2af4b07680b57'
        }
    ),
    (
        root,
        {
            'left': {
                'left': {
                    'hash': '9d6f467ca4962b97397eb9d228ff65a769b378083c7a7cacb50e6817de99bda7'
                },
                'right': {
                    'hash': '9ece01d833058a6603279663a23f08bfbf5f8ba2c4a00dc3581df5d0f599bdaa'
                },
                'hash': 'cd607f7f417c7f796bc863647558eb068d7f6400683978e32137c688ce128321'
            },
            'right': {
                'left': {
                    'hash': 'ff151d008c290d85c5e4bb53ee099ef975f093e36a8a3363f574bf256c44233f'
                },
                'right': {
                    'hash': '8d8740a5789e9371418549348e4467d62d995bd2f2b9339ef19fcc8467526b69'
                },
                'hash': '3c4dfc97969d64c2434ed613b1ad931af2dfac935407bf1b7ab2af4b07680b57'
            },
            'hash': 'd9186bdb6795c3f621ec8b3413f09ed7772b930c4d35da32d49b28d079d36f86'
        }
    )
]


@pytest.mark.parametrize("node, serialization", serializations)
def test_node_serialization(node, serialization):
    assert node.serialize() == serialization


json_texts = [
    (
        leaf1,
        '{\n    "hash": "9d6f467ca4962b97397eb9d228ff65a769b378083c7a7cacb50e6817de99bda7"\n}'
    ),
    (
        leaf2,
        '{\n    "hash": "9ece01d833058a6603279663a23f08bfbf5f8ba2c4a00dc3581df5d0f599bdaa"\n}'
    ),
    (
        leaf3,
        '{\n    "hash": "ff151d008c290d85c5e4bb53ee099ef975f093e36a8a3363f574bf256c44233f"\n}'
    ),
    (
        leaf4,
        '{\n    "hash": "8d8740a5789e9371418549348e4467d62d995bd2f2b9339ef19fcc8467526b69"\n}'
    ),

    (
        node12,
        '{\n    "hash": "cd607f7f417c7f796bc863647558eb068d7f6400683978e32137c688ce128321",\n\
    "left": {\n        "hash": "9d6f467ca4962b97397eb9d228ff65a769b378083c7a7cacb50e6817de99bda7"\n    },\n\
    "right": {\n        "hash": "9ece01d833058a6603279663a23f08bfbf5f8ba2c4a00dc3581df5d0f599bdaa"\n    }\n}'
    ),
    (
        node34,
        '{\n    "hash": "3c4dfc97969d64c2434ed613b1ad931af2dfac935407bf1b7ab2af4b07680b57",\n\
    "left": {\n        "hash": "ff151d008c290d85c5e4bb53ee099ef975f093e36a8a3363f574bf256c44233f"\n    },\n\
    "right": {\n        "hash": "8d8740a5789e9371418549348e4467d62d995bd2f2b9339ef19fcc8467526b69"\n    }\n}'
    ),
    (
        root,
        '{\n    "hash": "d9186bdb6795c3f621ec8b3413f09ed7772b930c4d35da32d49b28d079d36f86",\n\
    "left": {\n        "hash": "cd607f7f417c7f796bc863647558eb068d7f6400683978e32137c688ce128321",\n\
        "left": {\n            "hash": "9d6f467ca4962b97397eb9d228ff65a769b378083c7a7cacb50e6817de99bda7"\n        },\n\
        "right": {\n            "hash": "9ece01d833058a6603279663a23f08bfbf5f8ba2c4a00dc3581df5d0f599bdaa"\n        }\n    },\n\
    "right": {\n        "hash": "3c4dfc97969d64c2434ed613b1ad931af2dfac935407bf1b7ab2af4b07680b57",\n\
        "left": {\n            "hash": "ff151d008c290d85c5e4bb53ee099ef975f093e36a8a3363f574bf256c44233f"\n        },\n\
        "right": {\n            "hash": "8d8740a5789e9371418549348e4467d62d995bd2f2b9339ef19fcc8467526b69"\n        }\n    }\n}'
    )
]


@pytest.mark.parametrize("node, json_text", json_texts)
def test_node_toJSONtext(node, json_text):
    assert node.toJSONtext() == json_text
