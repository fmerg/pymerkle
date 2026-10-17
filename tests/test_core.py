import pytest

from pymerkle import InmemoryTree
from pymerkle.utils import decompose


def test_get_root(tree, start, end):
    offset = start
    subroots = []
    for p in reversed(decompose(end - start)):
        node = tree._get_subroot(offset, 1 << p)
        subroots += [node]
        offset += 1 << p

    subroots = list(reversed(subroots))
    root = subroots[0]
    index = 0
    while index < len(subroots) - 1:
        root = tree.hash_pair(subroots[index + 1], root)
        index += 1

    assert root == tree._get_root_naive(start, end)
    assert root == tree._get_root(start, end)


def test_state(tree, size):
    state = tree.get_root(size)

    assert state == tree._get_root_naive(0, size)
    assert state == tree._get_root(0, size)


def test_get_state_deprecated(tree, size):
    with pytest.warns(DeprecationWarning):
        assert tree.get_state(size) == tree.get_root(size)


def test_inclusion_path(tree):
    for size in range(1, tree.get_size() + 1):
        for index in range(1, size + 1):
            path1 = tree._inclusion_path(index, size)
            path2 = tree._inclusion_path_naive(index, size)

            assert path1 == path2


def test_consistency_path(tree):
    for size2 in range(1, tree.get_size() + 1):
        for size1 in range(size2 + 1):
            path1 = tree._consistency_path(size1, size2)
            path2 = tree._consistency_path_naive(size1, size2)

            assert path1 == path2


def test_state_bounds(tree):
    size = tree.get_size()

    if size == 0:
        assert tree.get_root() == tree.hash_empty()
        assert tree._get_root(0, 0) == tree._get_root_naive(0, 0)

    for invalid in (-1, size + 1):
        with pytest.raises(ValueError):
            tree.get_root(invalid)


@pytest.mark.default_config
def test_get_leaf_bounds(tree):
    size = tree.get_size()

    for invalid in (-1, 0, size + 1):
        with pytest.raises(ValueError):
            tree.get_leaf(invalid)


def test_unknown_option():
    with pytest.raises(TypeError):
        InmemoryTree(disable_cahce=True)


def test_append_entries():
    entries = [b'%d' % i for i in range(10)]
    tree = InmemoryTree.init_from_entries(entries[:3])

    assert tree.append_entries(e for e in entries[3:]) == len(entries)
    assert tree.append_entries([]) == len(entries)
    assert tree.get_root() == \
        InmemoryTree.init_from_entries(entries).get_root()
