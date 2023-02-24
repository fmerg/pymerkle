"""
Performs second preimage attack against Merkle-trees of all possible
combinations of hash and encoding types, for both possible security modes.

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
entries:       a   b   c   d               a   b


Concatenate the hashes stored by the 3-rd and 4-th leaves and append the result
3-rd leaf, leaving the rest leaves untouced.
"""

import pytest
from pymerkle import MerkleTree
from tests.conftest import all_configs, option


@pytest.mark.parametrize('config', all_configs(option))
def test_defense_against_second_preimage_attack(config):
    tree = MerkleTree.init_from_entries('a', 'b', 'c', 'd',
        **config)

    forged = tree.leaf(2) + tree.leaf(3)

    attacker = MerkleTree.init_from_entries('a', 'b', forged,
        **config)

    assert tree.security ^ (attacker.root == tree.root)
