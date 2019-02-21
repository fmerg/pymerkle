import pytest
import os
import json
import time
from pymerkle import MerkleTree, hashing, validateProof, ProofValidator
from pymerkle.validations import ValidationReceipt

# ---------------- Check receipt replicates in all possible ways ---------

tree = MerkleTree(*(bytes('{}-th record'.format(i), 'utf-8')
                    for i in range(0, 1000)))
p = tree.auditProof(666)
v = ProofValidator()
r = v.validate(target_hash=tree.rootHash(), proof=p)
r_1 = ValidationReceipt(from_json=r.JSONstring())
r_2 = ValidationReceipt(from_dict=json.loads(r.JSONstring()))


@pytest.mark.parametrize('replicate', (r_1, r_2))
def test_r_replicates_via_serialization(replicate):
    assert r.serialize() == replicate.serialize()

# ---------------------- Validation tests parametrization ----------------


HASH_TYPES = hashing.HASH_TYPES
ENCODINGS = ['utf_7',
             'utf_8',
             'utf_16',
             'utf_16_be',
             'utf_16_le',
             'utf_32',
             'utf_32_be',
             'utf_32_le']

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
        tree = MerkleTree(
            hash_type=hash_type,
            encoding=encoding,
            security=True,
            log_dir=os.path.join(current_dir, 'logs'))
        trees.append(tree)


@pytest.mark.parametrize('tree', trees)
def test_proof_validation_for_empty_tree(tree):
    """Tests proof-validation for proofs provided by empty trees
    """
    audit_proof = tree.auditProof(arg=0)
    consistency_proof = tree.consistencyProof(
        old_hash=tree.rootHash(), sublength=0)

    assert validateProof(
        target_hash=b'anything...',
        proof=audit_proof) is False and validateProof(
        target_hash=b'anything...',
        proof=consistency_proof) is False

# ------------------------ Test audit proof validation ------------------------


audit_proofs = []
target_hashes = []
expecteds = []

for bool_1 in (True, False):  # Controls index compatibility
    for bool_2 in (True, False):  # Controls validity of target hash
        for encoding in ENCODINGS:
            for hash_type in HASH_TYPES:
                for arg in range(first_log_size):

                    # Expected value configuration
                    expecteds.append(bool_1 and bool_2)

                    # Proof-provider configuration
                    tree = MerkleTree(
                        hash_type=hash_type,
                        encoding=encoding,
                        security=True,
                        log_dir=os.path.join(current_dir, 'logs'))
                    tree.encryptLog('short_APACHE_log')

                    # Proof configuration
                    if bool_1:
                        audit_proofs.append(tree.auditProof(arg=arg))
                    else:
                        audit_proofs.append(tree.auditProof(
                            arg=first_log_size + arg))

                    # Target-hash configuration
                    if bool_2:
                        target_hashes.append(tree.rootHash())
                    else:
                        target_hashes.append(b'anything else...')


@pytest.mark.parametrize(
    'audit_proof, target_hash, expected', [
        (audit_proofs[i], target_hashes[i], expecteds[i]) for i in range(
            len(audit_proofs))])
def test_index_based_audit_proof_validation_for_non_empty_tree(
        audit_proof, target_hash, expected):
    assert validateProof(
        target_hash=target_hash,
        proof=audit_proof) is expected


small_tree = MerkleTree('0', '1', '2', '3', '4', '5', '6', '7', '8', '9')
audit_proofs = []
expecteds = []

for bool in (True, False):
    for i in range(0, 10):
        if bool:
            audit_proofs.append(small_tree.auditProof(arg=str(i)))
        else:
            audit_proofs.append(small_tree.auditProof(arg=str(10 + i)))
        expecteds.append(bool)


@pytest.mark.parametrize(
    'audit_proof, expected', [
        (audit_proofs[i], expecteds[i]) for i in range(
            len(audit_proofs))])
def test_record_based_audit_proof_validation_for_non_empty_tree(
        audit_proof, expected):
    assert validateProof(
        target_hash=small_tree.rootHash(),
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
                        tree = MerkleTree(
                            hash_type=hash_type,
                            encoding=encoding,
                            security=True,
                            log_dir=os.path.join(current_dir, 'logs'))

                        # Append first log
                        tree.encryptLog('short_APACHE_log')

                        # Old-tree-hash configuration
                        if bool_1:
                            old_hash = tree.rootHash()
                        else:
                            old_hash = b'anything else...'

                        # Subtree-detection configuration
                        if bool_2 and bool_3:
                            old_tree_length = first_log_size
                        elif not bool_2 and bool_3:
                            old_tree_length = first_log_size - 1
                        else:
                            old_tree_length = second_log_size + first_log_size

                        # Update the tree by appending new log
                        tree.encryptLog('RED_HAT_LINUX_log')

                        # Generate proof for the above configurations
                        consistency_proofs.append(
                            tree.consistencyProof(
                                old_hash=old_hash,
                                sublength=old_tree_length))

                        # Target-hash configuration
                        if bool_4:
                            target_hashes.append(tree.rootHash())
                        else:
                            target_hashes.append(b'anything else...')


@pytest.mark.parametrize(
    'consistency_proof, target_hash, expected', [
        (consistency_proofs[i], target_hashes[i], expecteds[i]) for i in range(
            len(consistency_proofs))])
def test_consistency_proof_validation_for_non_empty_tree(
        consistency_proof, target_hash, expected):
    assert validateProof(
        target_hash=target_hash,
        proof=consistency_proof) is expected


# ------------------------- Test proof validator object ------------------

# Proof provider (a typical SHA256/UTF-8 Merkle-Tree with defense against
# second-preimage attack)
tree = MerkleTree(log_dir=os.path.join(current_dir, 'logs'))

# Proof validator
validator = ProofValidator(
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
    old_hash = tree.rootHash()
    old_length = len(tree.leaves)
    tree.encryptLog(log_file)
    proofs.append(
        tree.consistencyProof(
            old_hash=old_hash,
            sublength=old_length))
    target_hashes.append(tree.rootHash())


@pytest.mark.parametrize(
    'proof, target_hash', [
        (proofs[i], target_hashes[i]) for i in range(
            len(proofs))])
def test_ProofValidator(proof, target_hash):
    receipt = validator.validate(proof=proof, target_hash=target_hash)
    receipt_file_path = os.path.join(
        current_dir,
        'validations_dir',
        '{}.json'.format(
            receipt.header['uuid']))
    with open(receipt_file_path) as receipt_file:
        receipt_clone = json.load(receipt_file)
    assert receipt.serialize() == receipt_clone
