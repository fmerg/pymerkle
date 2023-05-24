import pytest
from tests.conftest import tree_and_index


@pytest.mark.parametrize('tree, subsize', tree_and_index(maxsize=11))
def test_state(tree, subsize):
    assert tree.get_state(subsize) == tree.hash_range(0, subsize)
    # TODO: Excapnd these test using binray decompositions
