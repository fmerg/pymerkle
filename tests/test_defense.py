""" Performs second-preimage attack against Merkle-trees of all possible hash- and encoding-types
for *both* possible security modes. Attack should succeed only when the tree's security mode is
deactiveated (i.e., *iff* its ``.security`` attribute is ``False`` by construction).

Attack Schema
-------------

               Original tree               Attacker's tree

                     A                           A
                   /   \                       /   \
                 B       C = h(FG)           B      C    ------> [injected leaf]
                / \     / \                 / \     |
 hashes:       D   E   F   G               D   E   (FG)  <------ [forged record]
               |   |   |   |               |   |
records:       d   e   f   g               d   e


Concatenate the hashes stored by the 3-rd and 4-th leaves and append the result (i.e., its hash)
as the 3-rd leaf, leaving the 1-st and 2-nd leaves untouched
"""
import pytest
from pymerkle import MerkleTree, hashing, encodings

# Generate trees for all combinations of hash and encoding types
# (including both security modes for each)
HASH_TYPES = hashing.HASH_TYPES
ENCODINGS = encodings.ENCODINGS
trees = []
for security in (True, False):
    for hash_type in HASH_TYPES:
        for encoding in ENCODINGS:
            trees.append(
                MerkleTree(
                    'a', 'b', 'c', 'd',  # original records
                    hash_type=hash_type,
                    encoding=encoding,
                    security=security
                )
            )


@pytest.mark.parametrize("original_tree", trees)
def test_defense_against_second_preimage_attack(original_tree):
    # Construct forged record
    F = original_tree.leaves[2].stored_hash.decode(
        encoding=original_tree.encoding)
    G = original_tree.leaves[3].stored_hash.decode(
        encoding=original_tree.encoding)
    forged_record = '%s%s' % (F, G)
    # Construct attacker's tree
    attacker_tree = MerkleTree(
        'a', 'b', forged_record,
        hash_type=original_tree.hash_type,
        encoding=original_tree.encoding,
        security=original_tree.security
    )
    # Check if the attacker has found the original root-hash
    if original_tree.security:
        assert original_tree.rootHash() != attacker_tree.rootHash()
    else:
        assert original_tree.rootHash() == attacker_tree.rootHash()
