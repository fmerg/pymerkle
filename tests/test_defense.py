"""
Performs second-preimage attack for both security modes. Attack should succeed
only when the tree's securitu mode has been disabled.

Attack schema
-------------

               Original tree               Attacker's tree

                     G                           G
                   /   \                       /   \
                 E       F = h(CD)           E       F    ------> [injected leaf]
                / \     / \                 / \      |
hashes:        A   B   C   D               A   B    (CD)  <------ [forged entry]
               |   |   |   |               |   |
entries:       a   b   c   d               a   b


Concatenate the 3-rd and 4-th leaf-hashes and append the result as 3-rd leaf,
leaving the rest leaves unoutched
"""

import pytest
from tests.conftest import all_configs, option, resolve_backend

MerkleTree = resolve_backend(option)


@pytest.mark.parametrize('config', all_configs(option))
def test_second_preimage_attack(config):
    tree = MerkleTree.init_from_entries([b'foo', b'bar', b'baz', b'qux'],
        **config)

    forged = tree.get_leaf(3) + tree.get_leaf(4)
    attacker = MerkleTree.init_from_entries([b'foo', b'bar', forged],
        **config)

    assert tree.security ^ (attacker.get_state() == tree.get_state())
