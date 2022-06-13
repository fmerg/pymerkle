import pytest
import json

from pymerkle.nodes import Node, Leaf, NODE_TEMPLATE
from pymerkle.hashing import HashEngine


engine = HashEngine()
encoding = engine.encoding

# Full binary structure: 4 leaves, 7 nodes in total
l1 = Leaf.from_record(b'first record...', engine)
l2 = Leaf.from_record(b'second record...', engine)
l3 = Leaf.from_record(b'third record...', engine)
l4 = Leaf.from_record(b'fourth record...', engine)
n1 = Node.from_children(l1, l2, engine)
n3 = Node.from_children(l3, l4, engine)
root = Node.from_children(n1, n3, engine)


stringifications = [
    (
        l1,
        '\n ├──9d6f467ca4962b97397eb9d228ff65a769b378083c7a7cacb50e6817de99bda7\n'
    ),
    (
        l2,
        '\n └──9ece01d833058a6603279663a23f08bfbf5f8ba2c4a00dc3581df5d0f599bdaa\n'
    ),
    (
        l3,
        '\n ├──ff151d008c290d85c5e4bb53ee099ef975f093e36a8a3363f574bf256c44233f\n'
    ),
    (
        l4,
        '\n └──8d8740a5789e9371418549348e4467d62d995bd2f2b9339ef19fcc8467526b69\n'
    ),
    (
        n1,
        '\n ├──cd607f7f417c7f796bc863647558eb068d7f6400683978e32137c688ce128321\n\
     ├──9d6f467ca4962b97397eb9d228ff65a769b378083c7a7cacb50e6817de99bda7\n\
     └──9ece01d833058a6603279663a23f08bfbf5f8ba2c4a00dc3581df5d0f599bdaa\n'
    ),
    (
        n3,
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

serializations = [
    (
        l1,
        {'hash':'9d6f467ca4962b97397eb9d228ff65a769b378083c7a7cacb50e6817de99bda7'}
    ),
    (
        l2,
        {'hash': '9ece01d833058a6603279663a23f08bfbf5f8ba2c4a00dc3581df5d0f599bdaa'}
    ),
    (
        l3,
        {'hash': 'ff151d008c290d85c5e4bb53ee099ef975f093e36a8a3363f574bf256c44233f'}
    ),
    (
        l4,
        {'hash': '8d8740a5789e9371418549348e4467d62d995bd2f2b9339ef19fcc8467526b69'}
    ),
    (
        n1,
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
        n3,
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


@pytest.mark.parametrize('node, stringification', stringifications)
def test___str__(node, stringification):
    assert node.__str__(encoding) == stringification


@pytest.mark.parametrize('node, serialization', serializations)
def test_node_serialization(node, serialization):
    assert node.serialize(encoding) == serialization


@pytest.mark.parametrize('node, serialized', serializations)
def test_node_toJSONtext(node, serialized):
    assert node.toJSONtext(encoding) == json.dumps(serialized, indent=4, sort_keys=True)
