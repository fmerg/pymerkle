from itertools import product
import pytest

from pymerkle.utils import decompose
from tests.conftest import option, make_trees, tree_and_index, tree_and_range


@pytest.mark.parametrize('tree, start, limit', tree_and_range())
def test_get_root(tree, start, limit):
    offset = start
    subroots = []
    for p in reversed(decompose(limit - start)):
        node = tree._get_subroot(offset, 1 << p)
        subroots += [node]
        offset += 1 << p

    subroots = list(reversed(subroots))
    root = subroots[0]
    index = 0
    while index < len(subroots) - 1:
        root = tree.hash_pair(subroots[index + 1], root)
        index += 1

    assert root == tree._get_root_naive(start, limit)
    assert root == tree._get_root(start, limit)


@pytest.mark.parametrize('tree, size', tree_and_index())
def test_state(tree, size):
    state = tree.get_state(size)

    assert state == tree._get_root_naive(0, size)
    assert state == tree._get_root(0, size)


@pytest.mark.parametrize('tree', make_trees())
def test_inclusion_path(tree):
    for size in range(1, tree.get_size() + 1):
        for pos in range(size):
            path1 = tree._inclusion_path(pos, size)
            path2 = tree._inclusion_path_naive(pos, size)

            assert path1 == path2


@pytest.mark.parametrize('tree', make_trees())
def test_consistency_path(tree):
    for size2 in range(1, tree.get_size() + 1):
        for size1 in range(size2 + 1):
            path1 = tree._consistency_path(size1, size2)
            path2 = tree._consistency_path_naive(size1, size2)

            assert path1 == path2


@pytest.mark.parametrize('tree', make_trees())
def test_state_bounds(tree):
    size = tree.get_size()

    if size == 0:
        assert tree.get_state() == tree.hash_empty()
        assert tree._get_root(0, 0) == tree._get_root_naive(0, 0)

    for invalid in (-1, size + 1):
        with pytest.raises(ValueError):
            tree.get_state(invalid)


@pytest.mark.parametrize('tree', make_trees(default_config=True))
def test_get_leaf_bounds(tree):
    size = tree.get_size()

    for invalid in (-1, 0, size + 1):
        with pytest.raises(ValueError):
            tree.get_leaf(invalid)


def test_unknown_option():
    from pymerkle import InmemoryTree

    with pytest.raises(TypeError):
        InmemoryTree(disable_cahce=True)


def test_append_entries():
    from pymerkle import InmemoryTree

    entries = [b'%d' % i for i in range(10)]
    tree = InmemoryTree.init_from_entries(entries[:3])

    assert tree.append_entries(e for e in entries[3:]) == len(entries)
    assert tree.append_entries([]) == len(entries)
    assert tree.get_state() == \
        InmemoryTree.init_from_entries(entries).get_state()
