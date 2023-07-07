from itertools import product
import pytest

from pymerkle.utils import decompose
from tests.conftest import option, trees, tree_and_index, tree_and_range


@pytest.mark.parametrize('tree', trees())
def test_append(tree):
    entry = b'foo'

    index = tree.append(entry)
    value = tree.get_leaf(index)

    assert index == tree.get_size()
    assert value == tree.hash_leaf(entry)


@pytest.mark.parametrize('tree, start, end', tree_and_range(maxsize=11))
def test_get_root_naive(tree, start, end):
    _start = start
    principals = []
    for p in list(reversed(decompose(end - start))):
        curr = tree.get_root(_start, _start + (1 << p))
        principals += [curr]
        _start += 1 << p

    principals = list(reversed(principals))
    result = principals[0]
    index = 0
    while index < len(principals) - 1:
        result = tree.hash_nodes(principals[index + 1], result)
        index += 1

    assert tree.get_root_naive(start, end) == result


@pytest.mark.parametrize('tree, start, end', tree_and_range(maxsize=11))
def test_get_root(tree, start, end):
    assert tree.get_root(start, end) == tree.get_root_naive(
            start, end)


@pytest.mark.parametrize('tree, size', tree_and_index(maxsize=11))
def test_state(tree, size):
    assert tree.get_state(size) == tree.get_root(0, size)
    assert tree.get_state(size) == tree.get_root_naive(0, size)


@pytest.mark.parametrize('tree, start, end', tree_and_range(maxsize=11))
def test_inclusion_path(tree, start, end):
    for bit, offset in product([0, 1], range(start, end)):
        path1 = tree.inclusion_path(start, offset, end, bit)
        path2 = tree.inclusion_path_naive(start, offset, end, bit)
        assert path1 == path2


@pytest.mark.parametrize('tree, lsize, rsize', tree_and_range(maxsize=11))
def test_consistency_path(tree, lsize, rsize):
    for bit1 in [0, 1]:
        bit2 = bit1
        path1 = tree.consistency_path(bit1, lsize, rsize, bit2)
        path2 = tree.consistency_path_naive(bit1, lsize, rsize, bit2)
        assert path1 == path2
