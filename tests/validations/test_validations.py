"""
Tests validation of Merkle-proofs
"""

import pytest
import os
import json

from pymerkle.hashing import HASH_TYPES
from pymerkle.exceptions import InvalidMerkleProof
from pymerkle import MerkleTree, Validator, validateProof
from pymerkle.validations.mechanisms import Receipt
from tests.config import ENCODINGS

# Merkle-proof validation

tree = MerkleTree(*[f'{i}-th record' for i in range(666)])
hash_func = tree.hash
subhash = tree.rootHash
sublength = tree.length

__challenges = [
    {
        'checksum': hash_func('100-th record')
    },
    {
        'checksum': hash_func(b'anything non recorded...')
    },
    {
        'subhash': subhash,
    },
    {
        'subhash': b'anything else...',
    },
]

@pytest.mark.parametrize('challenge', __challenges)
def test_validateResponse(challenge):
    proof = tree.merkleProof(challenge)
    commitment = proof.header['commitment']
    assert validateProof(proof) is validateProof(proof, commitment)

# Trees setup

MAX_LENGTH = 4

trees = []
for raw_bytes in (True, False):
    for security in (True, False):
        for length in range(1, MAX_LENGTH + 1):
            for hash_type in HASH_TYPES:
                for encoding in ENCODINGS:
                    trees.append(
                        MerkleTree(
                            *['%d-th record' % i for i in range(length)],
                            hash_type=hash_type,
                            encoding=encoding,
                            security=security
                        )
                    )


# Audit proof validation

__false_audit_proofs = []
__true_audit_proofs  = []

for tree in trees:

    __false_audit_proofs.append(
        (
            tree,
            tree.auditProof(b'anything that has not been recorded')
        )
    )

    for index in range(0, tree.length):
        __true_audit_proofs.append(
                (
                    tree,
                    tree.auditProof(tree.hash('%d-th record' % index))
                )
            )

@pytest.mark.parametrize("tree, proof", __false_audit_proofs)
def test_false_audit_validateProof(tree, proof):
    assert not validateProof(proof, tree.rootHash)

@pytest.mark.parametrize("tree, proof", __true_audit_proofs)
def test_true_audit_validateProof(tree, proof):
    assert validateProof(proof, tree.rootHash)


# Consistency proof validation

trees_and_subtrees = []

for tree in trees:
    for sublength in range(1, tree.length + 1):

        trees_and_subtrees.append(
            (
                tree,
                MerkleTree(
                    *['%d-th record' %_ for _ in range(sublength)],
                    hash_type=tree.hash_type,
                    encoding=tree.encoding,
                    raw_bytes=tree.raw_bytes,
                    security=tree.security
                )
            )
        )

__false_consistency_proofs = []
__true_consistency_proofs  = []

for (tree, subtree) in trees_and_subtrees:

        __false_consistency_proofs.append(
            (
                tree,
                tree.consistencyProof(b'anything except for the right hash')
            )
        )

        __true_consistency_proofs.append(
            (
                tree,
                tree.consistencyProof(subtree.rootHash)
            )
        )

@pytest.mark.parametrize("tree, consistency_proof", __false_consistency_proofs)
def test_false_consistency_validateProof(tree, consistency_proof):
    assert not validateProof(consistency_proof, tree.rootHash)

@pytest.mark.parametrize("tree, consistency_proof", __true_consistency_proofs)
def test_true_consistency_validateProof(tree, consistency_proof):
    assert validateProof(consistency_proof, tree.rootHash)


# Validator object

# test KeyError in validator construction

__missing_configs = [
        {
            'encoding': 0, 'raw_bytes': 0, 'security': 0,   # missing hash_type
        },
        {
            'hash_type': 0, 'raw_bytes': 0, 'security': 0,   # missing encoding
        },
        {
            'hash_type': 0, 'encoding': 0, 'security': 0,   # missing raw_bytes
        },
        {
            'hash_type': 0, 'encoding': 0, 'raw_bytes': 0,  # missing security
        },
]

@pytest.mark.parametrize('config', __missing_configs)
def test_validator_construction_error(config):
    with pytest.raises(KeyError):
        Validator(config)


# Test validator main exception

@pytest.mark.parametrize('tree, proof', __false_audit_proofs[:10])
def test_validator_with_false_proofs(tree, proof):
    validator = Validator(proof.get_validation_params())
    with pytest.raises(InvalidMerkleProof):
        validator.run(proof, tree.rootHash)
