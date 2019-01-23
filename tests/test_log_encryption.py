import pytest
import os
from pymerkle import merkle_tree, hashing

HASH_TYPES = hashing.HASH_TYPES
ENCODINGS = hashing.ENCODINGS

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
                merkle_tree(
                    hash_type=hash_type,
                    encoding=encoding,
                    security=security,
                    log_dir=os.path.join(current_dir, 'logs'))
            )


@pytest.mark.parametrize("tree", trees)
def test_encrypt_log(tree):

    clone_tree = merkle_tree(
        hash_type=tree.hash_type,
        encoding=tree.encoding,
        security=tree.security)

    # Update clone tree from records successively
    for record in records:
        clone_tree.update(record)

    # Update original tree directly from file
    tree.encrypt_log('short_APACHE_log')

    # Compare hashes
    assert tree.root_hash() == clone_tree.root_hash()
