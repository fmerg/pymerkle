import pytest

from pymerkle.nodes import Node, Leaf, NODE_TEMPLATE
from pymerkle.hashing import HashEngine


e = HashEngine()
hash_record = e.hash_record
hash_pair = e.hash_pair

pairs = (
    Leaf.from_record(b'some record...', hash_record),
    Leaf.from_record('5f4e54b52702884b03c21efc76b7433607fa3b35343b9fd322521c9c1ed633b4',
                     hash_record)
)

# Full binary structure (parent-child relations): 4 leaves, 7 nodes in total
leaf1 = Leaf.from_record(b'first record...', hash_record)
leaf2 = Leaf.from_record(b'second record...', hash_record)
leaf3 = Leaf.from_record(b'third record...', hash_record)
leaf4 = Leaf.from_record(b'fourth record...', hash_record)
node1 = Node.from_children(leaf1, leaf2, hash_pair)
node3 = Node.from_children(leaf3, leaf4, hash_pair)
root = Node.from_children(node1, node3, hash_pair)


# Childless leaves tests

@pytest.mark.parametrize('leaf', pairs)
def test_has_no_left_child(leaf):
    assert leaf.left is None


@pytest.mark.parametrize('leaf', pairs)
def test_leaf_has_no_right_child(leaf):
    assert leaf.right is None


@pytest.mark.parametrize('leaf', pairs)
def test_leaf_without_parent(leaf):
    assert leaf.parent is None


@pytest.mark.parametrize('leaf', pairs)
def test_parentless_leaf_is_not_left_child(leaf):
    assert not leaf.is_left_child()


@pytest.mark.parametrize('leaf', pairs)
def test_parentless_leaf_is_not_right_child(leaf):
    assert not leaf.is_right_child()


@pytest.mark.parametrize('leaf', pairs)
def test_parentless_leaf_no_ancestor_exception(leaf):
    assert not leaf.ancestor(degree=1)


def test_root_has_no_parent():
    assert root.parent is None


@pytest.mark.parametrize('node', (leaf1, leaf2, leaf3, leaf4))
def test_node_without_left(node):
    assert node.left is None


@pytest.mark.parametrize('node', (leaf1, leaf2, leaf3, leaf4))
def test_node_without_right(node):
    assert node.left is None


@pytest.mark.parametrize('node, parent', ((leaf1, node1), (leaf2, node1),
                                          (leaf3, node3), (leaf4, node3),
                                          (node1, root), (node3, root)))
def test_parent(node, parent):
    assert node.parent is parent


@pytest.mark.parametrize('node, left',
                         ((node1, leaf1), (node3, leaf3), (root, node1)))
def test_left_child(node, left):
    assert node.left is left


@pytest.mark.parametrize('node, right',
                         ((node1, leaf2), (node3, leaf4), (root, node3)))
def test_right_child(node, right):
    assert node.right is right


@pytest.mark.parametrize('node', (leaf1, leaf3, node1))
def test_is_left_child(node):
    assert node.is_left_child() and not node.is_right_child()


@pytest.mark.parametrize('node', (leaf2, leaf4, node3))
def test_is_right_child(node):
    assert node.is_right_child() and not node.is_left_child()


@pytest.mark.parametrize('node, degree', ((leaf1, 3), (leaf2, 3),
                                          (leaf3, 3), (leaf4, 3),
                                          (node1, 2), (node3, 2),
                                          (root, 1)))
def test_no_ancestor_exception(node, degree):
        assert not node.ancestor(degree=degree)


@pytest.mark.parametrize('node', (leaf1, leaf2, leaf3, leaf4,
                                  node1, node3, root))
def test_zero_degree_ancestor(node):
    assert node.ancestor(degree=0) is node


@pytest.mark.parametrize('node, expected', ((leaf1, node1), (leaf2, node1),
                                            (leaf3, node3), (leaf4, node3),
                                            (node1, root), (node3, root)))
def test_degree_one_ancestor(node, expected):
    assert node.ancestor(degree=1) is expected


@pytest.mark.parametrize('node', (leaf1, leaf2, leaf3, leaf4))
def test_degree_two_ancestor(node):
    assert node.ancestor(degree=2) is root


def test_hash_recalculation():
    new_leaf = Leaf.from_record(b'new record...', hash_record)
    node3.set_right(new_leaf)
    node3.recalculate_hash(hashfunc=hash_pair)
    root.recalculate_hash(hashfunc=hash_pair)
    assert node3.digest == hash_pair(leaf3.digest, new_leaf.digest) \
        and root.digest == hash_pair(node1.digest, node3.digest)
