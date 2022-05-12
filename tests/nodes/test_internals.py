"""
Tests construction and properies of nodes
"""

import pytest

from pymerkle.core.nodes import Node, Leaf, NODE_TEMPLATE
from pymerkle.hashing import HashEngine
from pymerkle.exceptions import NoAncestorException, UndecodableRecord


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


# Childless leaves tests

@pytest.mark.parametrize('leaf', pair_of_leaves)
def test_has_no_left_child(leaf):
    assert leaf.left is None


@pytest.mark.parametrize('leaf', pair_of_leaves)
def test_leaf_has_no_right_child(leaf):
    assert leaf.right is None


@pytest.mark.parametrize('leaf', pair_of_leaves)
def test_leaf_without_parent(leaf):
    assert leaf.parent is None


@pytest.mark.parametrize('leaf', pair_of_leaves)
def test_parentless_leaf_is_not_left_child(leaf):
    assert not leaf.is_left_child()


@pytest.mark.parametrize('leaf', pair_of_leaves)
def test_parentless_leaf_is_not_right_child(leaf):
    assert not leaf.is_right_child()


@pytest.mark.parametrize('leaf', pair_of_leaves)
def test_parentless_leaf_no_ancestor_exception(leaf):
    with pytest.raises(NoAncestorException):
        leaf.ancestor(degree=1)


@pytest.mark.parametrize('leaf', pair_of_leaves)
def test_parentless_leaf___repr__(leaf):
    assert leaf.__repr__() == NODE_TEMPLATE.format(node=str(hex(id(leaf))),
                                                   left='[None]',
                                                   right='[None]',
                                                   parent='[None]',
                                                   checksum=leaf.digest.decode(leaf.encoding))

def test_root_has_no_parent():
    assert root.parent is None


@pytest.mark.parametrize('node', (leaf1, leaf2, leaf3, leaf4))
def test_node_without_left(node):
    assert node.left is None


@pytest.mark.parametrize('node', (leaf1, leaf2, leaf3, leaf4))
def test_node_without_right(node):
    assert node.left is None


@pytest.mark.parametrize("node, parent", ((leaf1, node12), (leaf2, node12),
                                          (leaf3, node34), (leaf4, node34),
                                          (node12, root), (node34, root)))
def test_parent(node, parent):
    assert node.parent is parent


@pytest.mark.parametrize("node, left",
                         ((node12, leaf1), (node34, leaf3), (root, node12)))
def test_left_child(node, left):
    assert node.left is left


@pytest.mark.parametrize("node, right",
                         ((node12, leaf2), (node34, leaf4), (root, node34)))
def test_right_child(node, right):
    assert node.right is right


@pytest.mark.parametrize('node', (leaf1, leaf3, node12))
def test_is_left_child(node):
    assert node.is_left_child() and not node.is_right_child()


@pytest.mark.parametrize('node', (leaf2, leaf4, node34))
def test_is_right_child(node):
    assert node.is_right_child() and not node.is_left_child()


@pytest.mark.parametrize("node, degree", ((leaf1, 3), (leaf2, 3),
                                          (leaf3, 3), (leaf4, 3),
                                          (node12, 2), (node34, 2),
                                          (root, 1)))
def test_no_ancestor_exception(node, degree):
    with pytest.raises(NoAncestorException):
        node.ancestor(degree=degree)


@pytest.mark.parametrize('node', (leaf1, leaf2, leaf3, leaf4,
                                  node12, node34, root))
def test_zero_degree_ancestor(node):
    assert node.ancestor(degree=0) is node


@pytest.mark.parametrize("node, expected", ((leaf1, node12), (leaf2, node12),
                                            (leaf3, node34), (leaf4, node34),
                                            (node12, root), (node34, root)))
def test_degree_one_ancestor(node, expected):
    assert node.ancestor(degree=1) is expected


@pytest.mark.parametrize('node', (leaf1, leaf2, leaf3, leaf4))
def test_degree_two_ancestor(node):
    assert node.ancestor(degree=2) is root


def test_hash_recalculation():
    new_leaf = Leaf.from_record(b'new record...', hash_func, encoding)
    node34.set_right(new_leaf)
    node34.recalculate_hash(hash_func=hash_func)
    root.recalculate_hash(hash_func=hash_func)
    assert node34.digest == hash_func(leaf3.digest, new_leaf.digest) \
        and root.digest == hash_func(node12.digest, node34.digest)


# Decoding error tests

bytesengines = [
    (b'\xc2', HashEngine(encoding='ascii', raw_bytes=False, security=True)),
    (b'\xc2', HashEngine(encoding='ascii', raw_bytes=False, security=False)),
    (b'\x72', HashEngine(encoding='cp424', raw_bytes=False, security=True)),
    (b'\x72', HashEngine(encoding='cp424', raw_bytes=False, security=False)),
    (b'\xc2', HashEngine(encoding='hz', raw_bytes=False, security=True)),
    (b'\xc2', HashEngine(encoding='hz', raw_bytes=False, security=False)),
    (b'\xc2', HashEngine(encoding='utf_7', raw_bytes=False, security=True)),
    (b'\xc2', HashEngine(encoding='utf_7', raw_bytes=False, security=False)),
    (b'\x74', HashEngine(encoding='utf_16', raw_bytes=False, security=True)),
    (b'\x74', HashEngine(encoding='utf_16', raw_bytes=False, security=False)),
    (b'\x74', HashEngine(encoding='utf_16_le', raw_bytes=False, security=True)),
    (b'\x74', HashEngine(encoding='utf_16_le', raw_bytes=False, security=False)),
    (b'\x74', HashEngine(encoding='utf_16_be', raw_bytes=False, security=True)),
    (b'\x74', HashEngine(encoding='utf_16_be', raw_bytes=False, security=False)),
    (b'\x74', HashEngine(encoding='utf_32', raw_bytes=False, security=True)),
    (b'\x74', HashEngine(encoding='utf_32', raw_bytes=False, security=False)),
    (b'\x74', HashEngine(encoding='utf_32_le', raw_bytes=False, security=True)),
    (b'\x74', HashEngine(encoding='utf_32_le', raw_bytes=False, security=False)),
    (b'\x74', HashEngine(encoding='utf_32_be', raw_bytes=False, security=True)),
    (b'\x74', HashEngine(encoding='utf_32_be', raw_bytes=False, security=False)),
    (b'\xc2', HashEngine(encoding='iso2022_jp', raw_bytes=False, security=True)),
    (b'\xc2', HashEngine(encoding='iso2022_jp', raw_bytes=False, security=False)),
    (b'\xc2', HashEngine(encoding='iso2022_jp_1', raw_bytes=False, security=True)),
    (b'\xc2', HashEngine(encoding='iso2022_jp_1', raw_bytes=False, security=False)),
    (b'\xc2', HashEngine(encoding='iso2022_jp_2', raw_bytes=False, security=True)),
    (b'\xc2', HashEngine(encoding='iso2022_jp_2', raw_bytes=False, security=False)),
    (b'\xc2', HashEngine(encoding='iso2022_jp_3', raw_bytes=False, security=True)),
    (b'\xc2', HashEngine(encoding='iso2022_jp_3', raw_bytes=False, security=False)),
    (b'\xc2', HashEngine(encoding='iso2022_jp_ext', raw_bytes=False, security=True)),
    (b'\xc2', HashEngine(encoding='iso2022_jp_ext', raw_bytes=False, security=False)),
    (b'\xc2', HashEngine(encoding='iso2022_jp_2004', raw_bytes=False, security=True)),
    (b'\xc2', HashEngine(encoding='iso2022_jp_2004', raw_bytes=False, security=False)),
    (b'\xc2', HashEngine(encoding='iso2022_kr', raw_bytes=False, security=True)),
    (b'\xc2', HashEngine(encoding='iso2022_kr', raw_bytes=False, security=False)),
    (b'\xae', HashEngine(encoding='iso8859_3', raw_bytes=False, security=True)),
    (b'\xae', HashEngine(encoding='iso8859_3', raw_bytes=False, security=False)),
    (b'\xb6', HashEngine(encoding='iso8859_6', raw_bytes=False, security=True)),
    (b'\xb6', HashEngine(encoding='iso8859_6', raw_bytes=False, security=False)),
    (b'\xae', HashEngine(encoding='iso8859_7', raw_bytes=False, security=True)),
    (b'\xae', HashEngine(encoding='iso8859_7', raw_bytes=False, security=False)),
    (b'\xc2', HashEngine(encoding='iso8859_8', raw_bytes=False, security=True)),
    (b'\xc2', HashEngine(encoding='iso8859_8', raw_bytes=False, security=False)),
]
