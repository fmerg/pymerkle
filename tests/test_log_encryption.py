import pytest
import os
from pymerkle import MerkleTree, hashing, encodings

HASH_TYPES = hashing.HASH_TYPES
ENCODINGS = encodings.ENCODINGS

# Directory containing this script
current_dir = os.path.dirname(os.path.abspath(__file__))

# Load records line by line from file
records = []
with open(os.path.join(current_dir, 'logs/short_APACHE_log'), 'rb') as log_file:
    for line in log_file:
        records.append(line)

# Generate trees for all combinations of hash and encoding types
# (including both security modes for each)
trees = []
for security in (True, False):
    for hash_type in HASH_TYPES:
        for encoding in ENCODINGS:
            trees.append(
                MerkleTree(
                    hash_type=hash_type,
                    encoding=encoding,
                    security=security,
                    log_dir=os.path.join(current_dir, 'logs'))
            )


@pytest.mark.parametrize("tree", trees)
def test_encryptLog(tree):

    clone_tree = MerkleTree(
        hash_type=tree.hash_type,
        encoding=tree.encoding,
        security=tree.security)

    # Update clone tree from records successively
    for record in records:
        clone_tree.update(record)

    # Update original tree directly from file
    tree.encryptLog('short_APACHE_log')

    # Compare hashes
    assert tree.rootHash() == clone_tree.rootHash()
