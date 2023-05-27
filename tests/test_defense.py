"""
Performs second-preimage attack against for both possible security modes

Attack should succeed only when the tree's security mode is deactivated, that
is, iff the security attribute has been set to False at construction

Attack Schema
-------------

               Original tree               Attacker's tree

                     G                           G
                   /   \                       /   \
                 E       F = h(CD)           E      F    ------> [injected leaf]
                / \     / \                 / \     |
hashes:        D   B   C   D               A   B   (CD)  <------ [forged entry]
               |   |   |   |               |   |
entries:       A   b   c   d               a   b


Concatenate the hashes stored by the third and fourth leaves and append the result
as third leaf, leaving the rest leaves untouced
"""

import pytest
from tests.conftest import all_configs, option, resolve_backend

MerkleTree = resolve_backend(option)


@pytest.mark.parametrize('config', all_configs(option))
def test_second_preimage_attack(config):
    tree = MerkleTree.init_from_entries(b'a', b'b', b'c', b'd',
        **config)

    forged = tree.get_leaf(3) + tree.get_leaf(4)

    attacker = MerkleTree.init_from_entries(b'a', b'b', forged,
        **config)

    assert tree.security ^ (attacker.get_state() == tree.get_state())
