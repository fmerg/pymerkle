"""
Tests construction and properies of nodes
"""

import pytest

from pymerkle.core.nodes import Node, Leaf
from pymerkle.hashing import HashMachine
from pymerkle.exceptions import (NoChildException, NoDescendantException,
    NoParentException, LeafConstructionError, UndecodableRecord,)


_ = HashMachine()
encoding  = _.encoding
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


# Childless leaves tests

def test_leaf_construction_exception_with_neither_record_nor_digest():
    """
    Tests `TypeError` if neither `record` nor `digest` is provided
    """
    with pytest.raises(LeafConstructionError):
        Leaf(hash_func=hash_func, encoding=encoding)

def test_leaf_construction_exception_with_both_record_and_digest():
    """
    Tests `TypeError` if both `record` and `digest` are provided
    """
    with pytest.raises(LeafConstructionError):
        Leaf(hash_func=hash_func, encoding=encoding, record=b'anything...',
            digest=hash_func('whatever...'))

@pytest.mark.parametrize("leaf", pair_of_leaves)
def test_leaf_left_parent_exception(leaf):
    """
    Tests that invoking the ``.left``, ``.right`` and ``.child`` properties of
    a ``node.Leaf`` instance raises appropriate exceptions when
    these attributes are not available
    """
    with pytest.raises(NoParentException):
        leaf.left

@pytest.mark.parametrize("leaf", pair_of_leaves)
def test_leaf_right_parent_exception(leaf):
    """
    Tests that invoking the ``.left``, ``.right`` and ``.child`` properties of
    a ``node.Leaf`` instance raises appropriate exceptions when these attributes
    are not available
    """
    with pytest.raises(NoParentException):
        leaf.right

@pytest.mark.parametrize("leaf", pair_of_leaves)
def test_leaf_child_exception(leaf):
    """
    Tests that invoking the ``.left``, ``.right`` and ``.child`` properties of
    a ``node.Leaf`` instance raises appropriate exceptions when these attributes
    are not available
    """
    with pytest.raises(NoChildException):
        leaf.child

@pytest.mark.parametrize("leaf", pair_of_leaves)
def test_childless_leaf_is_not_left_parent(leaf):
    """
    Tests that ``.is_left_parent`` returns ``False`` for a leaf without child
    """
    assert not leaf.is_left_parent()

@pytest.mark.parametrize("leaf", pair_of_leaves)
def test_childless_leaf_is_not_right_parent(leaf):
    """
    Tests that ``.is_left_parent`` returns ``False`` for a leaf without a child
    """
    assert not leaf.is_right_parent()

@pytest.mark.parametrize("leaf", pair_of_leaves)
def test_childless_leaf_is_not_parent(leaf):
    """
    Tests that ``.is_left_parent`` returns ``False`` for a leaf without a child
    """
    assert not leaf.is_parent()

@pytest.mark.parametrize("leaf", pair_of_leaves)
def test_childless_leaf_no_descendant_exception(leaf):
    """
    Tests that the appropriate exception is raised when the descendant
    of a chidless leaf is requested
    """
    with pytest.raises(NoDescendantException):
        leaf.descendant(degree=1)

@pytest.mark.parametrize("leaf", pair_of_leaves)
def test_childless_leaf___repr__(leaf):
    """
    Tests that the representation of a childless leaf has the expected format
    """
    assert leaf.__repr__() == '\n    memory-id    : {self_id}\
                \n    left parent  : {left_id}\
                \n    right parent : {right_id}\
                \n    child        : {child_id}\
                \n    hash         : {hash}\n'\
                .format(self_id=str(hex(id(leaf))),
                        left_id='[None]',
                        right_id='[None]',
                        child_id='[None]',
                        hash=leaf.digest.decode(leaf.encoding))


# Leaves with children and internal nodes tests

# Exception tests

def test_no_child_exception():
    """
    Tests that NoChildException is raised for the unique childless node
    """
    with pytest.raises(NoChildException):
        root.child

@pytest.mark.parametrize("node", (leaf_1, leaf_2, leaf_3, leaf_4))
def test_no_parent_exception_for_left(node):
    """
    Tests NoParentException with `.light` for all parentless cases
    """
    with pytest.raises(NoParentException):
        node.left


@pytest.mark.parametrize("node", (leaf_1, leaf_2, leaf_3, leaf_4))
def test_no_parent_exception_for_right(node):
    """
    Tests NoParentException with `.right` for all parentless cases
    """
    with pytest.raises(NoParentException):
        node.right


# Child-parent relation tests

@pytest.mark.parametrize("node, child", ((leaf_1, node_12), (leaf_2, node_12),
                                        (leaf_3, node_34), (leaf_4, node_34),
                                        (node_12, root), (node_34, root)))
def test_child(node, child):
    """
    Tests child for all valid cases
    """
    assert node.child is child

@pytest.mark.parametrize("node, left",
    ((node_12, leaf_1), (node_34, leaf_3), (root, node_12)))
def test_left_parent(node, left):
    """
    Tests left parent for all valid cases
    """
    assert node.left is left


@pytest.mark.parametrize("node, right",
    ((node_12, leaf_2), (node_34, leaf_4), (root, node_34)))
def test_right_parent(node, right):
    """
    Tests left parent for all valid cases
    """
    assert node.right is right


@pytest.mark.parametrize("node", (leaf_1, leaf_3, node_12))
def test_is_left_parent(node):
    """
    Tests a node's property of being a left parent
    (excluding the possibility of being right parent)
    """
    assert node.is_left_parent() and not node.is_right_parent()


@pytest.mark.parametrize("node", (leaf_2, leaf_4, node_34))
def test_is_right_parent(node):
    """
    Tests a node's property of being a right parent
    (excluding the possibility of being left parent)
    """
    assert node.is_right_parent() and not node.is_left_parent()


@pytest.mark.parametrize("node, expected", ((leaf_1, True), (leaf_2, True),
                                            (leaf_4, True), (leaf_4, True),
                                            (node_12, True), (node_34, True),
                                            (root, False)))
def test_is_parent(node, expected):
    """
    Tests a node's property of being a parent
    """
    assert node.is_parent() is expected


# Descendancy tests

@pytest.mark.parametrize("node, degree", ((leaf_1, 3), (leaf_2, 3),
                                           (leaf_3, 3), (leaf_4, 3),
                                           (node_12, 2), (node_34, 2),
                                           (root, 1)))
def test_no_descendant_exception(node, degree):
    """
    Tests that NoDescendantException is raised for the minimum
    degree of descendancy exceeding all possibilities
    """
    with pytest.raises(NoDescendantException):
        node.descendant(degree=degree)

@pytest.mark.parametrize("node", (leaf_1, leaf_2, leaf_3, leaf_4,
                                node_12, node_34, root))
def test_zero_degree_descendant(node):
    """
    Tests that zero degree descendancy points to the node itself
    """
    assert node.descendant(degree=0) is node

@pytest.mark.parametrize("node, expected", ((leaf_1, node_12), (leaf_2, node_12),
                                             (leaf_3, node_34), (leaf_4, node_34),
                                             (node_12, root), (node_34, root)))
def test_degree_one_descendant(node, expected):
    """
    Tests descendancy of degree 1 for all valid cases
    """
    assert node.descendant(degree=1) is expected


@pytest.mark.parametrize("node", (leaf_1, leaf_2, leaf_3, leaf_4))
def test_degree_two_descendant(node):
    """
    Tests descendancy  of degree 2 for all valid cases
    """
    assert node.descendant(degree=2) is root


# Recalculation tests

def test_hash_recalculation():
    new_leaf = Leaf(hash_func=hash_func, encoding=encoding, record=b'new record...')
    node_34.set_right(new_leaf)
    node_34.recalculate_hash(hash_func=hash_func)
    root.recalculate_hash(hash_func=hash_func)
    assert node_34.digest == hash_func(leaf_3.digest, new_leaf.digest) \
    and root.digest == hash_func(node_12.digest, node_34.digest)


# Decoding error tests

__bytes__machines = [
    (b'\xc2', HashMachine(encoding='ascii',           raw_bytes=False, security=True)),
    (b'\xc2', HashMachine(encoding='ascii',           raw_bytes=False, security=False)),
    (b'\x72', HashMachine(encoding='cp424',           raw_bytes=False, security=True)),
    (b'\x72', HashMachine(encoding='cp424',           raw_bytes=False, security=False)),
    (b'\xc2', HashMachine(encoding='hz',              raw_bytes=False, security=True)),
    (b'\xc2', HashMachine(encoding='hz',              raw_bytes=False, security=False)),
    (b'\xc2', HashMachine(encoding='utf_7',           raw_bytes=False, security=True)),
    (b'\xc2', HashMachine(encoding='utf_7',           raw_bytes=False, security=False)),
    (b'\x74', HashMachine(encoding='utf_16',          raw_bytes=False, security=True)),
    (b'\x74', HashMachine(encoding='utf_16',          raw_bytes=False, security=False)),
    (b'\x74', HashMachine(encoding='utf_16_le',       raw_bytes=False, security=True)),
    (b'\x74', HashMachine(encoding='utf_16_le',       raw_bytes=False, security=False)),
    (b'\x74', HashMachine(encoding='utf_16_be',       raw_bytes=False, security=True)),
    (b'\x74', HashMachine(encoding='utf_16_be',       raw_bytes=False, security=False)),
    (b'\x74', HashMachine(encoding='utf_32',          raw_bytes=False, security=True)),
    (b'\x74', HashMachine(encoding='utf_32',          raw_bytes=False, security=False)),
    (b'\x74', HashMachine(encoding='utf_32_le',       raw_bytes=False, security=True)),
    (b'\x74', HashMachine(encoding='utf_32_le',       raw_bytes=False, security=False)),
    (b'\x74', HashMachine(encoding='utf_32_be',       raw_bytes=False, security=True)),
    (b'\x74', HashMachine(encoding='utf_32_be',       raw_bytes=False, security=False)),
    (b'\xc2', HashMachine(encoding='iso2022_jp',      raw_bytes=False, security=True)),
    (b'\xc2', HashMachine(encoding='iso2022_jp',      raw_bytes=False, security=False)),
    (b'\xc2', HashMachine(encoding='iso2022_jp_1',    raw_bytes=False, security=True)),
    (b'\xc2', HashMachine(encoding='iso2022_jp_1',    raw_bytes=False, security=False)),
    (b'\xc2', HashMachine(encoding='iso2022_jp_2',    raw_bytes=False, security=True)),
    (b'\xc2', HashMachine(encoding='iso2022_jp_2',    raw_bytes=False, security=False)),
    (b'\xc2', HashMachine(encoding='iso2022_jp_3',    raw_bytes=False, security=True)),
    (b'\xc2', HashMachine(encoding='iso2022_jp_3',    raw_bytes=False, security=False)),
    (b'\xc2', HashMachine(encoding='iso2022_jp_ext',  raw_bytes=False, security=True)),
    (b'\xc2', HashMachine(encoding='iso2022_jp_ext',  raw_bytes=False, security=False)),
    (b'\xc2', HashMachine(encoding='iso2022_jp_2004', raw_bytes=False, security=True)),
    (b'\xc2', HashMachine(encoding='iso2022_jp_2004', raw_bytes=False, security=False)),
    (b'\xc2', HashMachine(encoding='iso2022_kr',      raw_bytes=False, security=True)),
    (b'\xc2', HashMachine(encoding='iso2022_kr',      raw_bytes=False, security=False)),
    (b'\xae', HashMachine(encoding='iso8859_3',       raw_bytes=False, security=True)),
    (b'\xae', HashMachine(encoding='iso8859_3',       raw_bytes=False, security=False)),
    (b'\xb6', HashMachine(encoding='iso8859_6',       raw_bytes=False, security=True)),
    (b'\xb6', HashMachine(encoding='iso8859_6',       raw_bytes=False, security=False)),
    (b'\xae', HashMachine(encoding='iso8859_7',       raw_bytes=False, security=True)),
    (b'\xae', HashMachine(encoding='iso8859_7',       raw_bytes=False, security=False)),
    (b'\xc2', HashMachine(encoding='iso8859_8',       raw_bytes=False, security=True)),
    (b'\xc2', HashMachine(encoding='iso8859_8',       raw_bytes=False, security=False)),
]

@pytest.mark.parametrize('byte, machine', __bytes__machines)
def test_leaf_UndecodableRecord(byte, machine):
    with pytest.raises(UndecodableRecord):
        Leaf(record=byte, encoding=machine.encoding, hash_func=machine.hash)

@pytest.mark.parametrize('byte, machine', __bytes__machines)
def test_node_UndecodableRecord(byte, machine):
    with pytest.raises(UndecodableRecord):
        left = Leaf(record=byte, encoding=machine.encoding,
            hash_func=machine.hash)
        _right = Leaf(record=byte, encoding=machine.encoding,
            hash_func=machine.hash)
        with pytest.raises(UndecodableRecord):
            Node(left=left, right=_right, encoding=machine.encoding,
                hash_func=machine.hash)

@pytest.mark.parametrize('byte, machine', __bytes__machines)
def test_hash_recalculation_UndecodableRecord(byte, machine):
    with pytest.raises(UndecodableRecord):
        left = Leaf(record='left record', encoding=machine.encoding,
            hash_func=machine.hash)
        right = Leaf(record='right record', encoding=machine.encoding,
            hash_func=machine.hash)
        node = Node(left=left, right=right, encoding=machine.encoding,
            hash_func=machine.hash)
        left = Leaf(record=byte, encoding=machine.encoding,
            hash_func=machine.hash)
        node.set_left(_left)
        node.recalculate_hash(machine.hash)
