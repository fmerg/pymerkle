import pytest

from pymerkle.nodes import Node, Leaf, NODE_TEMPLATE
from pymerkle.hashing import HashEngine


engine = HashEngine()

pairs = (
    Leaf.from_record(b'some record...', engine),
    Leaf.from_record('5f4e54b52702884b03c21efc76b7433607fa3b35343b9fd322521c9c1ed633b4',
                     engine)
)

# Full binary structure: 4 leaves, 7 nodes in total
l1 = Leaf.from_record(b'a', engine)
l2 = Leaf.from_record(b'b', engine)
l3 = Leaf.from_record(b'c', engine)
l4 = Leaf.from_record(b'd', engine)
n1 = Node.from_children(l1, l2, engine)
n3 = Node.from_children(l3, l4, engine)
root = Node.from_children(n1, n3, engine)


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


@pytest.mark.parametrize('node', (l1, l2, l3, l4))
def test_node_without_left(node):
    assert node.left is None


@pytest.mark.parametrize('node', (l1, l2, l3, l4))
def test_node_without_right(node):
    assert node.left is None


@pytest.mark.parametrize('node, parent', ((l1, n1), (l2, n1),
                                          (l3, n3), (l4, n3),
                                          (n1, root), (n3, root)))
def test_parent(node, parent):
    assert node.parent is parent


@pytest.mark.parametrize('node, left',
                         ((n1, l1), (n3, l3), (root, n1)))
def test_left_child(node, left):
    assert node.left is left


@pytest.mark.parametrize('node, right',
                         ((n1, l2), (n3, l4), (root, n3)))
def test_right_child(node, right):
    assert node.right is right


@pytest.mark.parametrize('node', (l1, l3, n1))
def test_is_left_child(node):

    assert all((
        node.is_left_child(),
        not node.is_right_child(),
    ))


@pytest.mark.parametrize('node', (l2, l4, n3))
def test_is_right_child(node):

    assert all((
        node.is_right_child(),
        not node.is_left_child(),
    ))


@pytest.mark.parametrize('node, degree', ((l1, 3), (l2, 3),
                                          (l3, 3), (l4, 3),
                                          (n1, 2), (n3, 2),
                                          (root, 1)))
def test_no_ancestor_exception(node, degree):
    assert not node.ancestor(degree=degree)


@pytest.mark.parametrize('node', (l1, l2, l3, l4,
                                  n1, n3, root))
def test_zero_degree_ancestor(node):
    assert node.ancestor(degree=0) is node


@pytest.mark.parametrize('node, expected', ((l1, n1), (l2, n1),
                                            (l3, n3), (l4, n3),
                                            (n1, root), (n3, root)))
def test_degree_one_ancestor(node, expected):
    assert node.ancestor(degree=1) is expected


@pytest.mark.parametrize('node', (l1, l2, l3, l4))
def test_degree_two_ancestor(node):
    assert node.ancestor(degree=2) is root


def test_hash_recalculation():
    new_leaf = Leaf.from_record(b'new record...', engine)
    n3.set_right(new_leaf)
    n3.recalculate_hash(engine)
    root.recalculate_hash(engine)

    assert all((
        n3.digest == engine.hash_pair(l3.digest, new_leaf.digest),
        root.digest == engine.hash_pair(n1.digest, n3.digest),
    ))
