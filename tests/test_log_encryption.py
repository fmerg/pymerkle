import pytest
import os
from pymerkle import merkle_tree, hash_tools

HASH_TYPES = hash_tools.HASH_TYPES
ENCODINGS = hash_tools.ENCODINGS

# Directory containing this script
current_dir = os.path.dirname(os.path.abspath(__file__))

# Load records line by line from file
records = []
with open(os.path.join(current_dir, 'logs/APACHE_log'), 'rb') as log_file:
    for line in log_file:
        records.append(line)

tree_pairs = []
for security in (True, False):
    for hash_type in HASH_TYPES:
        for encoding in ENCODINGS:
            tree_pairs.append(
                (
                    # Will load successively from records
                    merkle_tree(
                        hash_type=hash_type,
                        encoding=encoding,
                        security=security),

                    # Will load directly from file
                    merkle_tree(
                        hash_type=hash_type,
                        encoding=encoding,
                        security=security,
                        logs_dir=os.path.join(current_dir, 'logs'))
                )
            )


@pytest.mark.parametrize(
    "tree_1, tree_2", [
        (pair[0], pair[1]) for pair in tree_pairs])
def test_encrypt_log(tree_1, tree_2):

    # Update first tree from records successively
    for record in records:
        tree_1.update(record)

    # Update second tree directly from file
    tree_2.encrypt_log('APACHE_log')

    # Compare hashes
    assert tree_1.root_hash() == tree_2.root_hash()
