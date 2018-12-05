import pytest
import os
from pymerkle import merkle_tree, validate_proof, proof_validator, hash_tools

HASH_TYPES = hash_tools.HASH_TYPES
ENCODINGS = ['utf_7',
             'utf_8',
             'utf_32',
             'utf_16']

# Directory containing this script
current_dir = os.path.dirname(os.path.abspath(__file__))

# First log size
with open(os.path.join(current_dir, 'logs/short_APACHE_log')) as first_log_file:
    first_log_size = sum(1 for line in first_log_file)

# Second log size
with open(os.path.join(current_dir, 'logs/RED_HAT_LINUX_log')) as second_log_file:
    second_log_size = sum(1 for line in second_log_file)

# ------------------------------ Empty tree case ------------------------------

trees = []
for encoding in ENCODINGS:
    for hash_type in HASH_TYPES:
        tree = merkle_tree(
            hash_type=hash_type,
            encoding=encoding,
            security=True,
            log_dir=os.path.join(current_dir, 'logs'))
        trees.append(tree)


@pytest.mark.parametrize('tree', trees)
def test_proof_validation_for_empty_tree(tree):
    """
    Tests proof-validation for proofs provided by empty trees
    """
    audit_proof = tree.audit_proof(index=0)
    consistency_proof = tree.consistency_proof(
        old_tree_hash=tree.root_hash(), sublength=0)

    assert validate_proof(
        target_hash='anything...',
        proof=audit_proof) is False and validate_proof(
        target_hash='anything...',
        proof=consistency_proof) is False

# ------------------------ Test audit proof validation ------------------------


audit_proofs = []
target_hashes = []
expecteds = []

for bool_1 in (True, False):  # Controls index compatibility
    for bool_2 in (True, False):  # Controls validity of target hash
        for encoding in ENCODINGS:
            for hash_type in HASH_TYPES:
                for index in range(first_log_size):

                    # Expected value configuration
                    expecteds.append(bool_1 and bool_2)

                    # Proof-provider configuration
                    tree = merkle_tree(
                        hash_type=hash_type,
                        encoding=encoding,
                        security=True,
                        log_dir=os.path.join(current_dir, 'logs'))
                    tree.encrypt_log('short_APACHE_log')
                    # trees.append(tree)

                    # Proof configuration
                    if bool_1:
                        audit_proofs.append(tree.audit_proof(index=index))
                    else:
                        audit_proofs.append(tree.audit_proof(
                            index=first_log_size + index))

                    # Target-hash configuration
                    if bool_2:
                        target_hashes.append(tree.root_hash())
                    else:
                        target_hashes.append('anything else...')


@pytest.mark.parametrize(
    'audit_proof, target_hash, expected', [
        (audit_proofs[i], target_hashes[i], expecteds[i]) for i in range(
            len(audit_proofs))])
def test_audit_proof_validation_for_non_empty_tree(
        audit_proof, target_hash, expected):
    assert validate_proof(
        target_hash=target_hash,
        proof=audit_proof) is expected

# --------------------- Test Consistency proof validation ---------------------


consistency_proofs = []
target_hashes = []
expecteds = []

for bool_1 in (
        True,
        False):  # Controls subtree detection via validity of old tree hash
    for bool_2 in (
            True, False):  # Controls subtree detection via its length
        for bool_3 in (
                True, False):  # Controls subtree compatibility
            for bool_4 in (
                    True, False):  # Controls validity of target hash
                for encoding in ENCODINGS:
                    for hash_type in HASH_TYPES:

                        # Expected value configuration
                        expecteds.append(
                            bool_1 and bool_2 and bool_3 and bool_4)

                        # Proof-provider configuration
                        tree = merkle_tree(
                            hash_type=hash_type,
                            encoding=encoding,
                            security=True,
                            log_dir=os.path.join(current_dir, 'logs'))

                        # Append first log
                        tree.encrypt_log('short_APACHE_log')

                        # Old-tree-hash configuration
                        if bool_1:
                            old_tree_hash = tree.root_hash()
                        else:
                            old_tree_hash = 'anything else...'

                        # Subtree-detection configuration
                        if bool_2 and bool_3:
                            old_tree_length = first_log_size
                        elif not bool_2 and bool_3:
                            old_tree_length = first_log_size - 1
                        else:
                            old_tree_length = second_log_size + first_log_size

                        # Update the tree by appending new log
                        tree.encrypt_log('RED_HAT_LINUX_log')

                        # Generate proof for the above configurations
                        consistency_proofs.append(
                            tree.consistency_proof(
                                old_tree_hash=old_tree_hash,
                                sublength=old_tree_length))

                        # Target-hash configuration
                        if bool_4:
                            target_hashes.append(tree.root_hash())
                        else:
                            target_hashes.append('anything else...')


@pytest.mark.parametrize(
    'consistency_proof, target_hash, expected', [
        (consistency_proofs[i], target_hashes[i], expecteds[i]) for i in range(
            len(consistency_proofs))])
def test_consistency_proof_validation_for_non_empty_tree(
        consistency_proof, target_hash, expected):
    # assert 0 == 0
    assert validate_proof(
        target_hash=target_hash,
        proof=consistency_proof) is expected
