from itertools import product
import pytest

from pymerkle.utils import decompose
from tests.conftest import option, trees, tree_and_index, tree_and_range


@pytest.mark.parametrize('tree, start, end', tree_and_range(maxsize=11))
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
    hash_nodes = tree.hash_nodes
    while index < len(subroots) - 1:
        root = hash_nodes(subroots[index + 1], root)
        index += 1

    assert root == tree._get_root_naive(start, end)
    assert root == tree._get_root(start, end)


@pytest.mark.parametrize('tree, size', tree_and_index(maxsize=11))
def test_state(tree, size):
    state = tree.get_state(size)

    assert state == tree._get_root_naive(0, size)
    assert state == tree._get_root(0, size)


@pytest.mark.parametrize('tree, start, end', tree_and_range(maxsize=11))
def test_inclusion_path(tree, start, end):
    for bit, offset in product([0, 1], range(start, end)):
        path1 = tree._inclusion_path(start, offset, end, bit)
        path2 = tree._inclusion_path_naive(start, offset, end, bit)

        assert path1 == path2


@pytest.mark.parametrize('tree, lsize, rsize', tree_and_range(maxsize=11))
def test_consistency_path(tree, lsize, rsize):
    for bit1, bit2 in product([0, 1], [0, 1]):
        path1 = tree._consistency_path(bit1, lsize, rsize, bit2)
        path2 = tree._consistency_path_naive(bit1, lsize, rsize, bit2)

        assert path1 == path2
