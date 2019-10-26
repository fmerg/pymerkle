"""
Tests represenation and serialization of nodes
"""

import pytest

from pymerkle.core.nodes import Node, Leaf
from pymerkle.hashing import HashMachine


_ = HashMachine()
encoding = _.encoding
hash_func = _.hash

pair_of_leaves = (
    Leaf(hash_func=hash_func, encoding=encoding, record=b'some record...'),
    Leaf(hash_func=hash_func, encoding=encoding,
        digest='5f4e54b52702884b03c21efc76b7433607fa3b35343b9fd322521c9c1ed633b4'))

# Full binary structure (child-parent relations): 4 leaves, 7 nodes in total
leaf_1  = Leaf(hash_func=hash_func, encoding=encoding, record=b'first record...')
leaf_2  = Leaf(hash_func=hash_func, encoding=encoding, record=b'second record...')
leaf_3  = Leaf(hash_func=hash_func, encoding=encoding, record=b'third record...')
leaf_4  = Leaf(hash_func=hash_func, encoding=encoding, record=b'fourth record...')
node_12 = Node(hash_func=hash_func, encoding=encoding, left=leaf_1, right=leaf_2)
node_34 = Node(hash_func=hash_func, encoding=encoding, left=leaf_3, right=leaf_4)
root    = Node(hash_func=hash_func, encoding=encoding, left=node_12, right=node_34)


@pytest.mark.parametrize("leaf", (leaf_1, leaf_2, leaf_3, leaf_4))
def test___repr__for_leafs_with_child(leaf):
    assert leaf.__repr__() == '\n    memory-id    : {self_id}\
                \n    left parent  : {left_id}\
                \n    right parent : {right_id}\
                \n    child        : {child_id}\
                \n    hash         : {hash}\n'\
                .format(self_id=str(hex(id(leaf))),
                        left_id='[None]',
                        right_id='[None]',
                        child_id=str(hex(id(leaf.child))),
                        hash=leaf.digest.decode(leaf.encoding))


@pytest.mark.parametrize("node", (node_12, node_34))
def test___repr__for_nodes_with_child(node):
    assert node.__repr__() == '\n    memory-id    : {self_id}\
                \n    left parent  : {left_id}\
                \n    right parent : {right_id}\
                \n    child        : {child_id}\
                \n    hash         : {hash}\n'\
                .format(self_id=str(hex(id(node))),
                        left_id=str(hex(id(node.left))),
                        right_id=str(hex(id(node.right))),
                        child_id=str(hex(id(node.child))),
                        hash=node.digest.decode(node.encoding))

def test___repr__for_node_without_child():
    assert root.__repr__() == '\n    memory-id    : {self_id}\
                \n    left parent  : {left_id}\
                \n    right parent : {right_id}\
                \n    child        : {child_id}\
                \n    hash         : {hash}\n'\
                .format(self_id=str(hex(id(root))),
                        left_id=str(hex(id(root.left))),
                        right_id=str(hex(id(root.right))),
                        child_id='[None]',
                        hash=root.digest.decode(root.encoding))


stringifications = [
    (
        leaf_1,
        '\n ├──9d6f467ca4962b97397eb9d228ff65a769b378083c7a7cacb50e6817de99bda7\n'
    ),
    (
        leaf_2,
        '\n └──9ece01d833058a6603279663a23f08bfbf5f8ba2c4a00dc3581df5d0f599bdaa\n'
    ),
    (
        leaf_3,
        '\n ├──ff151d008c290d85c5e4bb53ee099ef975f093e36a8a3363f574bf256c44233f\n'
    ),
    (
        leaf_4,
        '\n └──8d8740a5789e9371418549348e4467d62d995bd2f2b9339ef19fcc8467526b69\n'
    ),
    (
        node_12,
        '\n ├──cd607f7f417c7f796bc863647558eb068d7f6400683978e32137c688ce128321\n\
     ├──9d6f467ca4962b97397eb9d228ff65a769b378083c7a7cacb50e6817de99bda7\n\
     └──9ece01d833058a6603279663a23f08bfbf5f8ba2c4a00dc3581df5d0f599bdaa\n'
    ),
    (
        node_34,
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
        node_12,
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
        node_34,
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


toJSONStrings = [
    (
        leaf_1,
        '{\n    "hash": "9d6f467ca4962b97397eb9d228ff65a769b378083c7a7cacb50e6817de99bda7"\n}'
    ),
    (
        leaf_2,
        '{\n    "hash": "9ece01d833058a6603279663a23f08bfbf5f8ba2c4a00dc3581df5d0f599bdaa"\n}'
    ),
    (
        leaf_3,
        '{\n    "hash": "ff151d008c290d85c5e4bb53ee099ef975f093e36a8a3363f574bf256c44233f"\n}'
    ),
    (
        leaf_4,
        '{\n    "hash": "8d8740a5789e9371418549348e4467d62d995bd2f2b9339ef19fcc8467526b69"\n}'
    ),

    (
        node_12,
        '{\n    "hash": "cd607f7f417c7f796bc863647558eb068d7f6400683978e32137c688ce128321",\n\
    "left": {\n        "hash": "9d6f467ca4962b97397eb9d228ff65a769b378083c7a7cacb50e6817de99bda7"\n    },\n\
    "right": {\n        "hash": "9ece01d833058a6603279663a23f08bfbf5f8ba2c4a00dc3581df5d0f599bdaa"\n    }\n}'
    ),
    (
        node_34,
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

@pytest.mark.parametrize("node, json_string", toJSONStrings)
def test_node_toJSONString(node, json_string):
    assert node.toJSONString() == json_string
