import pytest
import os
import json
import time
from pymerkle import merkle_tree, hash_tools, validate_proof, proof_validator

HASH_TYPES = hash_tools.HASH_TYPES
ENCODINGS = ['utf_7',
             'utf_8',
             'utf_32',
             'utf_16']

# Directory containing this script
current_dir = os.path.dirname(os.path.abspath(__file__))

# Store first log size
with open(os.path.join(current_dir, 'logs/short_APACHE_log')) as first_log_file:
    first_log_size = sum(1 for line in first_log_file)

# Store second log size
with open(os.path.join(current_dir, 'logs/RED_HAT_LINUX_log')) as second_log_file:
    second_log_size = sum(1 for line in second_log_file)

# ------------------- Test validate proof for empty tree case ------------

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
        old_hash=tree.root_hash(), sublength=0)

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

# --------------------- Test consistency proof validation ---------------------


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
                            old_hash = tree.root_hash()
                        else:
                            old_hash = 'anything else...'

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
                                old_hash=old_hash,
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
    assert validate_proof(
        target_hash=target_hash,
        proof=consistency_proof) is expected


# ------------------------- Test proof validator object ------------------

# Proof provider (a typical SHA256/UTF-8 merkle-tree with defense against
# second-preimage attack)
tree = merkle_tree(log_dir=os.path.join(current_dir, 'logs'))

# Proof validator
validator = proof_validator(
    validations_dir=os.path.join(
        current_dir, 'validations_dir'))

# Clean validations directory before running the test
file_list = os.listdir(os.path.join(
    current_dir, 'validations_dir'))
for file in file_list:
    os.remove(os.path.join(
        current_dir, 'validations_dir', file))

# Feed tree with logs gradually and generate consistency proof for each step
proofs = []
target_hashes = []
for log_file in ('large_APACHE_log', 'RED_HAT_LINUX_log', 'short_APACHE_log'):
    old_hash = tree.root_hash()
    old_length = len(tree.leaves)
    tree.encrypt_log(log_file)
    proofs.append(
        tree.consistency_proof(
            old_hash=old_hash,
            sublength=old_length))
    target_hashes.append(tree.root_hash())


@pytest.mark.parametrize(
    'proof, target_hash', [
        (proofs[i], target_hashes[i]) for i in range(
            len(proofs))])
def test_proof_validator(proof, target_hash):
    receipt = validator.validate(proof=proof, target_hash=target_hash)
    receipt_file_path = os.path.join(
        current_dir,
        'validations_dir',
        '{}.json'.format(
            receipt.header['id']))
    with open(receipt_file_path) as receipt_file:
        receipt_clone = json.load(receipt_file)
    assert receipt.serialize() == receipt_clone
