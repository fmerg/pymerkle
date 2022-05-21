"""
Performs 2nd-preimage attack against Merkle-trees of all possible combinations of
hash and encoding types, for *both* possible security modes.

Attack should succeed *only* when the tree's security mode is deactivated, that
is, *iff* the ``.security`` attribute has been set to ``False`` at construction

Attack Schema
-------------

               Original tree               Attacker's tree

                     A                           A
                   /   \                       /   \
                 B       C = h(FG)           B      C    ------> [injected leaf]
                / \     / \                 / \     |
digests:       D   E   F   G               D   E   (FG)  <------ [forged record]
               |   |   |   |               |   |
records:       d   e   f   g               d   e


Concatenate the digests stored by the 3-rd and 4-th leaves and append the result
(i.e., its digest) as the 3-rd leaf, leaving the 1-st and 2-nd leaves untouched
"""

import pytest

from pymerkle import MerkleTree
from pymerkle.hashing import SUPPORTED_HASH_TYPES

from tests.conftest import option, resolve_encodings


trees = []
for security in (True, False):
    for hash_type in SUPPORTED_HASH_TYPES:
        for encoding in resolve_encodings(option):
            config = {'hash_type': hash_type, 'encoding': encoding,
                      'security': security}
            tree = MerkleTree.init_from_records('a', 'b', 'c', 'd',
                                                config=config)
            trees.append(tree)


@pytest.mark.parametrize('original', trees)
def test_defense_against_second_preimage_attack(original):

    # Construct forged record
    F = original.leaves[2].digest
    G = original.leaves[3].digest
    forged = F + G

    # Attacker's tree
    attacker = MerkleTree.init_from_records('a', 'b', forged,
                                            config=original.get_config())

    # Check if the attacker has replicated the original root-hash
    if original.security:
        assert original.root_hash != attacker.root_hash
    else:
        assert original.root_hash == attacker.root_hash
