"""
Tests construction and properies of nodes
"""

import pytest

from pymerkle.core.nodes import Node, Leaf
from pymerkle.hashing import HashEngine
from pymerkle.exceptions import (NoParentException, NoAncestorException,
                                 NoChildException, LeafConstructionError, UndecodableRecord,)


_ = HashEngine()
encoding = _.encoding
hash_func = _.hash

pair_of_leaves = (
    Leaf(hash_func=hash_func, encoding=encoding, record=b'some record...'),
    Leaf(hash_func=hash_func, encoding=encoding,
         digest='5f4e54b52702884b03c21efc76b7433607fa3b35343b9fd322521c9c1ed633b4'))

# Full binary structure (parent-child relations): 4 leaves, 7 nodes in total
leaf_1 = Leaf(hash_func=hash_func, encoding=encoding,
              record=b'first record...')
leaf_2 = Leaf(hash_func=hash_func, encoding=encoding,
              record=b'second record...')
leaf_3 = Leaf(hash_func=hash_func, encoding=encoding,
              record=b'third record...')
leaf_4 = Leaf(hash_func=hash_func, encoding=encoding,
              record=b'fourth record...')
node_12 = Node(hash_func=hash_func, encoding=encoding,
               left=leaf_1, right=leaf_2)
node_34 = Node(hash_func=hash_func, encoding=encoding,
               left=leaf_3, right=leaf_4)
root = Node(hash_func=hash_func, encoding=encoding,
            left=node_12, right=node_34)


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
def test_leaf_left_child_exception(leaf):
    """
    Tests that invoking the ``.left``, ``.right`` and ``.parent`` properties of
    a ``node.Leaf`` instance raises appropriate exceptions when
    these attributes are not available
    """
    with pytest.raises(NoChildException):
        leaf.left


@pytest.mark.parametrize("leaf", pair_of_leaves)
def test_leaf_right_child_exception(leaf):
    """
    Tests that invoking the ``.left``, ``.right`` and ``.parent`` properties of
    a ``node.Leaf`` instance raises appropriate exceptions when these attributes
    are not available
    """
    with pytest.raises(NoChildException):
        leaf.right


@pytest.mark.parametrize("leaf", pair_of_leaves)
def test_leaf_parent_exception(leaf):
    """
    Tests that invoking the ``.left``, ``.right`` and ``.parent`` properties of
    a ``node.Leaf`` instance raises appropriate exceptions when these attributes
    are not available
    """
    with pytest.raises(NoParentException):
        leaf.parent


@pytest.mark.parametrize("leaf", pair_of_leaves)
def test_parentless_leaf_is_not_left_child(leaf):
    """
    Tests that ``.is_left_child`` returns ``False`` for a leaf without parent
    """
    assert not leaf.is_left_child()


@pytest.mark.parametrize("leaf", pair_of_leaves)
def test_parentless_leaf_is_not_right_child(leaf):
    """
    Tests that ``.is_left_child`` returns ``False`` for a leaf without a parent
    """
    assert not leaf.is_right_child()


@pytest.mark.parametrize("leaf", pair_of_leaves)
def test_parentless_leaf_is_not_child(leaf):
    """
    Tests that ``.is_left_child`` returns ``False`` for a leaf without a parent
    """
    assert not leaf.is_child()


@pytest.mark.parametrize("leaf", pair_of_leaves)
def test_parentless_leaf_no_ancestor_exception(leaf):
    """
    Tests that the appropriate exception is raised when the ancestor
    of a chidless leaf is requested
    """
    with pytest.raises(NoAncestorException):
        leaf.ancestor(degree=1)


@pytest.mark.parametrize("leaf", pair_of_leaves)
def test_parentless_leaf___repr__(leaf):
    """
    Tests that the representation of a parentless leaf has the expected format
    """
    assert leaf.__repr__() == '\n    memory-id    : {self_id}\
                \n    left child  : {left_id}\
                \n    right child : {right_id}\
                \n    parent        : {parent_id}\
                \n    hash         : {hash}\n'\
                .format(self_id=str(hex(id(leaf))),
                        left_id='[None]',
                        right_id='[None]',
                        parent_id='[None]',
                        hash=leaf.digest.decode(leaf.encoding))


# Leaves with parentren and internal nodes tests

# Exception tests

def test_no_parent_exception():
    """
    Tests that NoParentException is raised for the unique parentless node
    """
    with pytest.raises(NoParentException):
        root.parent


@pytest.mark.parametrize("node", (leaf_1, leaf_2, leaf_3, leaf_4))
def test_no_child_exception_for_left(node):
    """
    Tests NoChildException with `.light` for all childless cases
    """
    with pytest.raises(NoChildException):
        node.left


@pytest.mark.parametrize("node", (leaf_1, leaf_2, leaf_3, leaf_4))
def test_no_child_exception_for_right(node):
    """
    Tests NoChildException with `.right` for all childless cases
    """
    with pytest.raises(NoChildException):
        node.right


# Child-child relation tests

@pytest.mark.parametrize("node, parent", ((leaf_1, node_12), (leaf_2, node_12),
                                         (leaf_3, node_34), (leaf_4, node_34),
                                         (node_12, root), (node_34, root)))
def test_parent(node, parent):
    """
    Tests parent for all valid cases
    """
    assert node.parent is parent


@pytest.mark.parametrize("node, left",
                         ((node_12, leaf_1), (node_34, leaf_3), (root, node_12)))
def test_left_child(node, left):
    """
    Tests left child for all valid cases
    """
    assert node.left is left


@pytest.mark.parametrize("node, right",
                         ((node_12, leaf_2), (node_34, leaf_4), (root, node_34)))
def test_right_child(node, right):
    """
    Tests left child for all valid cases
    """
    assert node.right is right


@pytest.mark.parametrize("node", (leaf_1, leaf_3, node_12))
def test_is_left_child(node):
    """
    Tests a node's property of being a left child
    (excluding the possibility of being right child)
    """
    assert node.is_left_child() and not node.is_right_child()


@pytest.mark.parametrize("node", (leaf_2, leaf_4, node_34))
def test_is_right_child(node):
    """
    Tests a node's property of being a right child
    (excluding the possibility of being left child)
    """
    assert node.is_right_child() and not node.is_left_child()


@pytest.mark.parametrize("node, expected", ((leaf_1, True), (leaf_2, True),
                                            (leaf_4, True), (leaf_4, True),
                                            (node_12, True), (node_34, True),
                                            (root, False)))
def test_is_child(node, expected):
    """
    Tests a node's property of being a child
    """
    assert node.is_child() is expected


# Descendancy tests

@pytest.mark.parametrize("node, degree", ((leaf_1, 3), (leaf_2, 3),
                                          (leaf_3, 3), (leaf_4, 3),
                                          (node_12, 2), (node_34, 2),
                                          (root, 1)))
def test_no_ancestor_exception(node, degree):
    """
    Tests that NoAncestorException is raised for the minimum
    degree of descendancy exceeding all possibilities
    """
    with pytest.raises(NoAncestorException):
        node.ancestor(degree=degree)


@pytest.mark.parametrize("node", (leaf_1, leaf_2, leaf_3, leaf_4,
                                  node_12, node_34, root))
def test_zero_degree_ancestor(node):
    """
    Tests that zero degree descendancy points to the node itself
    """
    assert node.ancestor(degree=0) is node


@pytest.mark.parametrize("node, expected", ((leaf_1, node_12), (leaf_2, node_12),
                                            (leaf_3, node_34), (leaf_4, node_34),
                                            (node_12, root), (node_34, root)))
def test_degree_one_ancestor(node, expected):
    """
    Tests descendancy of degree 1 for all valid cases
    """
    assert node.ancestor(degree=1) is expected


@pytest.mark.parametrize("node", (leaf_1, leaf_2, leaf_3, leaf_4))
def test_degree_two_ancestor(node):
    """
    Tests descendancy  of degree 2 for all valid cases
    """
    assert node.ancestor(degree=2) is root


# Recalculation tests

def test_hash_recalculation():
    new_leaf = Leaf(hash_func=hash_func, encoding=encoding,
                    record=b'new record...')
    node_34.set_right(new_leaf)
    node_34.recalculate_hash(hash_func=hash_func)
    root.recalculate_hash(hash_func=hash_func)
    assert node_34.digest == hash_func(leaf_3.digest, new_leaf.digest) \
        and root.digest == hash_func(node_12.digest, node_34.digest)


# Decoding error tests

bytesengines = [
    (b'\xc2', HashEngine(encoding='ascii',           raw_bytes=False, security=True)),
    (b'\xc2', HashEngine(encoding='ascii',           raw_bytes=False, security=False)),
    (b'\x72', HashEngine(encoding='cp424',           raw_bytes=False, security=True)),
    (b'\x72', HashEngine(encoding='cp424',           raw_bytes=False, security=False)),
    (b'\xc2', HashEngine(encoding='hz',              raw_bytes=False, security=True)),
    (b'\xc2', HashEngine(encoding='hz',              raw_bytes=False, security=False)),
    (b'\xc2', HashEngine(encoding='utf_7',           raw_bytes=False, security=True)),
    (b'\xc2', HashEngine(encoding='utf_7',           raw_bytes=False, security=False)),
    (b'\x74', HashEngine(encoding='utf_16',          raw_bytes=False, security=True)),
    (b'\x74', HashEngine(encoding='utf_16',          raw_bytes=False, security=False)),
    (b'\x74', HashEngine(encoding='utf_16_le',       raw_bytes=False, security=True)),
    (b'\x74', HashEngine(encoding='utf_16_le',       raw_bytes=False, security=False)),
    (b'\x74', HashEngine(encoding='utf_16_be',       raw_bytes=False, security=True)),
    (b'\x74', HashEngine(encoding='utf_16_be',       raw_bytes=False, security=False)),
    (b'\x74', HashEngine(encoding='utf_32',          raw_bytes=False, security=True)),
    (b'\x74', HashEngine(encoding='utf_32',          raw_bytes=False, security=False)),
    (b'\x74', HashEngine(encoding='utf_32_le',       raw_bytes=False, security=True)),
    (b'\x74', HashEngine(encoding='utf_32_le',       raw_bytes=False, security=False)),
    (b'\x74', HashEngine(encoding='utf_32_be',       raw_bytes=False, security=True)),
    (b'\x74', HashEngine(encoding='utf_32_be',       raw_bytes=False, security=False)),
    (b'\xc2', HashEngine(encoding='iso2022_jp',      raw_bytes=False, security=True)),
    (b'\xc2', HashEngine(encoding='iso2022_jp',      raw_bytes=False, security=False)),
    (b'\xc2', HashEngine(encoding='iso2022_jp_1',    raw_bytes=False, security=True)),
    (b'\xc2', HashEngine(encoding='iso2022_jp_1',    raw_bytes=False, security=False)),
    (b'\xc2', HashEngine(encoding='iso2022_jp_2',    raw_bytes=False, security=True)),
    (b'\xc2', HashEngine(encoding='iso2022_jp_2',    raw_bytes=False, security=False)),
    (b'\xc2', HashEngine(encoding='iso2022_jp_3',    raw_bytes=False, security=True)),
    (b'\xc2', HashEngine(encoding='iso2022_jp_3',    raw_bytes=False, security=False)),
    (b'\xc2', HashEngine(encoding='iso2022_jp_ext',  raw_bytes=False, security=True)),
    (b'\xc2', HashEngine(encoding='iso2022_jp_ext',  raw_bytes=False, security=False)),
    (b'\xc2', HashEngine(encoding='iso2022_jp_2004', raw_bytes=False, security=True)),
    (b'\xc2', HashEngine(encoding='iso2022_jp_2004', raw_bytes=False, security=False)),
    (b'\xc2', HashEngine(encoding='iso2022_kr',      raw_bytes=False, security=True)),
    (b'\xc2', HashEngine(encoding='iso2022_kr',      raw_bytes=False, security=False)),
    (b'\xae', HashEngine(encoding='iso8859_3',       raw_bytes=False, security=True)),
    (b'\xae', HashEngine(encoding='iso8859_3',       raw_bytes=False, security=False)),
    (b'\xb6', HashEngine(encoding='iso8859_6',       raw_bytes=False, security=True)),
    (b'\xb6', HashEngine(encoding='iso8859_6',       raw_bytes=False, security=False)),
    (b'\xae', HashEngine(encoding='iso8859_7',       raw_bytes=False, security=True)),
    (b'\xae', HashEngine(encoding='iso8859_7',       raw_bytes=False, security=False)),
    (b'\xc2', HashEngine(encoding='iso8859_8',       raw_bytes=False, security=True)),
    (b'\xc2', HashEngine(encoding='iso8859_8',       raw_bytes=False, security=False)),
]


@pytest.mark.parametrize('byte, engine', bytesengines)
def test_leaf_UndecodableRecord(byte, engine):
    with pytest.raises(UndecodableRecord):
        Leaf(record=byte, encoding=engine.encoding, hash_func=engine.hash)


@pytest.mark.parametrize('byte, engine', bytesengines)
def test_node_UndecodableRecord(byte, engine):
    with pytest.raises(UndecodableRecord):
        left = Leaf(record=byte, encoding=engine.encoding,
                    hash_func=engine.hash)
        _right = Leaf(record=byte, encoding=engine.encoding,
                      hash_func=engine.hash)
        with pytest.raises(UndecodableRecord):
            Node(left=left, right=_right, encoding=engine.encoding,
                 hash_func=engine.hash)


@pytest.mark.parametrize('byte, engine', bytesengines)
def test_hash_recalculation_UndecodableRecord(byte, engine):
    with pytest.raises(UndecodableRecord):
        left = Leaf(record='left record', encoding=engine.encoding,
                    hash_func=engine.hash)
        right = Leaf(record='right record', encoding=engine.encoding,
                     hash_func=engine.hash)
        node = Node(left=left, right=right, encoding=engine.encoding,
                    hash_func=engine.hash)
        left = Leaf(record=byte, encoding=engine.encoding,
                    hash_func=engine.hash)
        node.set_left(_left)
        node.recalculate_hash(engine.hash)
