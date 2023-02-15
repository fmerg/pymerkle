"""
Performs second preimage attack against Merkle-trees of all possible
combinations of hash and encoding types, for both possible security modes.

Attack should succeed only when the tree's security mode is deactivated, that
is, iff the security attribute has been set to False at construction

Attack Schema
-------------

               Original tree               Attacker's tree

                     A                           A
                   /   \                       /   \
                 B       C = h(FG)           B      C    ------> [injected leaf]
                / \     / \                 / \     |
digests:       D   E   F   G               D   E   (FG)  <------ [forged entry]
               |   |   |   |               |   |
entries:       d   e   f   g               d   e


Concatenate the digests stored by the 3-rd and 4-th leaves and append the result
(i.e., its digest) as the 3-rd leaf, leaving the 1-st and 2-nd leaves untouched
"""

import pytest
from pymerkle import MerkleTree
from tests.conftest import option, all_configs


@pytest.mark.parametrize('config', all_configs(option))
def test_defense_against_second_preimage_attack(config):
    original = MerkleTree.init_from_entries(
        'a', 'b', 'c', 'd', config=config
    )

    F = original.get_leaf(2).value
    G = original.get_leaf(3).value
    forged = F + G

    attacker = MerkleTree.init_from_entries(
        'a', 'b', forged, config=original.get_config()
    )

    if original.security:
        assert original.get_root_hash() != attacker.get_root_hash()
    else:
        assert original.get_root_hash() == attacker.get_root_hash()
