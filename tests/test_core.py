from itertools import product
import pytest

from pymerkle.utils import decompose
from tests.conftest import option, tree_and_index, tree_and_range


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
        root = tree._hash_nodes(subroots[index + 1], root)
        index += 1

    assert root == tree._get_root_naive(start, limit)
    assert root == tree._get_root(start, limit)


@pytest.mark.parametrize('tree, size', tree_and_index())
def test_state(tree, size):
    state = tree.get_state(size)

    assert state == tree._get_root_naive(0, size)
    assert state == tree._get_root(0, size)


@pytest.mark.parametrize('tree, start, limit', tree_and_range())
def test_inclusion_path(tree, start, limit):
    for bit, offset in product([0, 1], range(start, limit)):
        path1 = tree._inclusion_path(start, offset, limit, bit)
        path2 = tree._inclusion_path_naive(start, offset, limit, bit)

        assert path1 == path2


@pytest.mark.parametrize('tree, size1, size2', tree_and_range())
def test_consistency_path(tree, size1, size2):
    for bit1, bit2 in product([0, 1], [0, 1]):
        path1 = tree._consistency_path(bit1, size1, size2, bit2)
        path2 = tree._consistency_path_naive(bit1, size1, size2, bit2)

        assert path1 == path2
