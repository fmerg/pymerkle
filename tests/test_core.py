import pytest

from pymerkle.utils import decompose
from tests.conftest import option, trees, tree_and_index, tree_and_range


@pytest.mark.parametrize('tree', trees())
def test_append(tree):
    entry = b'foo'

    index = tree.append(entry)
    value = tree.get_leaf(index)

    assert index == tree.get_size()
    assert value == tree.hash_leaf(entry).hex()


@pytest.mark.parametrize('tree, start, end', tree_and_range(maxsize=11))
def test_hash_range(tree, start, end):
    _start = start
    principals = []
    for p in list(reversed(decompose(end - start))):
        curr = tree.hash_range(_start, _start + (1 << p))
        principals += [curr]
        _start += 1 << p

    principals = list(reversed(principals))
    result = principals[0]
    index = 0
    while index < len(principals) - 1:
        result = tree.hash_nodes(principals[index + 1], result)
        index += 1

    assert tree.hash_range(start, end) == result


@pytest.mark.parametrize('tree, subsize', tree_and_index(maxsize=11))
def test_state(tree, subsize):
    assert tree.get_state(subsize) == tree.hash_range(0, subsize).hex()

    principals = []
    start = 0
    for p in list(reversed(decompose(subsize))):
        curr = tree.hash_range(start, start + (1 << p))
        principals += [curr]
        start += 1 << p

    principals = list(reversed(principals))
    result = principals[0]
    index = 0
    while index < len(principals) - 1:
        result = tree.hash_nodes(principals[index + 1], result)
        index += 1

    assert tree.get_state(subsize) == result.hex()
