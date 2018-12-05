import pytest
import os
from pymerkle import merkle_tree, hash_tools

HASH_TYPES = hash_tools.HASH_TYPES
ENCODINGS = hash_tools.ENCODINGS

# Directory containing this script
current_dir = os.path.dirname(os.path.abspath(__file__))

# Load records line by line from file
records = []
with open(os.path.join(current_dir, 'logs/short_APACHE_log'), 'rb') as log_file:
    for line in log_file:
        records.append(line)

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

    # Update clone tree from records successively
    test_tree = merkle_tree(
        hash_type=tree.hash_type,
        encoding=tree.encoding,
        security=tree.security)
    for record in records:
        test_tree.update(record)

    # Update second tree directly from file
    tree.encrypt_log('short_APACHE_log')

    # Compare hashes
    assert tree.root_hash() == test_tree.root_hash()
