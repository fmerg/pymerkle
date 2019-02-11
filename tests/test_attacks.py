""" Performs second-preimage attack against Merkle-trees of all possible hash- and
encoding-types. Attack should succeed *iff* the tree's security mode is deactiveated
"""
import pytest
from pymerkle import merkle_tree, hashing, encodings

# Generate trees for all combinations of hash and encoding types
# (including both security modes for each)
trees = []
for security in (True, False):
    for hash_type in HASH_TYPES:
        for encoding in ENCODINGS:
            trees.append(
                merkle_tree(
                    hash_type=hash_type,
                    encoding=encoding,
                    security=security
            )
