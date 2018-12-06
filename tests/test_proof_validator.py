import pytest
import os
from pymerkle import merkle_tree, proof_validator

# Directory containing this script
current_dir = os.path.dirname(os.path.abspath(__file__))

# Store first log size
with open(os.path.join(current_dir, 'logs/RED_HAT_LINUX_log')) as first_log_file:
    first_log_size = sum(1 for line in first_log_file)

# Store second log size
with open(os.path.join(current_dir, 'logs/short_APACHE_log')) as second_log_file:
    second_log_size = sum(1 for line in second_log_file)

# Proof provider (a typical SHA256/UTF-8 merkle-tree with defence against
# second-preimage attack)
tree = merkle_tree(log_dir=os.path.join(current_dir, 'logs'))

# Proof validator
validator = proof_validator(
    validator_database=os.path.join(
        current_dir, 'validator_database'))

# Feed tree with logs
old_hash_0 = tree.root_hash()  # is None
old_length_0 = len(tree.leaves)  # is 0
tree.encrypt_log('RED_HAT_LINUX_log')
consistency_proof_1 = tree.consistency_proof(
    old_tree_hash=old_hash_0, sublength=old_length_0)
target_hash_1 = tree.root_hash()
old_hash_1 = tree.root_hash()
old_length_1 = len(tree.leaves)  # is first_log_size
tree.encrypt_log('short_APACHE_log')
consistency_proof_2 = tree.consistency_proof(
    old_tree_hash=old_hash_1, sublength=old_length_1)
target_hash_2 = tree.root_hash()


def test_test():
    validator.validate(
        proof=consistency_proof_1,
        target_hash=target_hash_1)
    assert 0 == 0
