"""
Performs 2nd-preimage attack against Merkle-trees of all possible combinations of
hash-type, encoding-type and raw-bytes mode, for *both* possible security modes

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
from pymerkle.hashing import HASH_TYPES
from tests.config import ENCODINGS

trees = []
for raw_bytes in (True, False):
    for security in (True, False):
        for hash_type in HASH_TYPES:
            for encoding in ENCODINGS:
                trees.append(
                    MerkleTree('a', 'b', 'c', 'd',            # original records
                        hash_type=hash_type,
                        encoding=encoding,
                        raw_bytes=raw_bytes,
                        security=security
                    )
                )


@pytest.mark.parametrize("original_tree", trees)
def test_defense_against_second_preimage_attack(original_tree):

    # Construct forged record
    leaves = original_tree.leaves
    encoding = original_tree.encoding
    if original_tree.raw_bytes:
        F = leaves[2].digest
        G = leaves[3].digest
    else:
        F = leaves[2].digest.decode(encoding)
        G = leaves[3].digest.decode(encoding)
    forged_record = F + G

    # Attacker's tree
    attacker_tree = MerkleTree('a', 'b', forged_record,         # forged records
        hash_type=original_tree.hash_type,
        encoding=original_tree.encoding,
        raw_bytes=original_tree.raw_bytes,
        security=original_tree.security
    )

    # Check if the attacker has replicated the original root-hash
    if original_tree.security:
        assert original_tree.rootHash != attacker_tree.rootHash
    else:
        assert original_tree.rootHash == attacker_tree.rootHash
