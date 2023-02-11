"""
Tests verification of Merkle-proofs
"""

import os
import json
import pytest
from pymerkle.prover import InvalidProof
from pymerkle import MerkleTree
from tests.conftest import option, all_configs


# Merkle-proof verification

def test_verify_proof_with_target():
    tree = MerkleTree.init_from_records(
        *[f'{i}-th record' for i in range(666)])
    proof = tree.generate_audit_proof(tree.hash_data('100-th record'))
    assert proof.verify() is proof.verify(target=proof.commitment)


# Trees setup


max_length = 4
trees = []
for config in all_configs(option):
    for length in range(1, max_length + 1):
        tree = MerkleTree.init_from_records(
            *['%d-th record' % i for i in range(length)],
            config=config)
        trees.append(tree)


# Audit proof verification

false_audit_proofs = []
valid_audit_proofs = []

for tree in trees:
    false_audit_proofs.append(
        (
            tree,
            tree.generate_audit_proof(b'anything that has not been recorded')
        )
    )

    for index in range(0, tree.length):
        valid_audit_proofs.append(
            (
                tree,
                tree.generate_audit_proof(tree.hash_data('%d-th record' % index))
            )
        )


@pytest.mark.parametrize('tree, proof', false_audit_proofs)
def test_false_audit_verify_proof(tree, proof):
    with pytest.raises(InvalidProof):
        proof.verify(target=tree.get_root_hash())


@pytest.mark.parametrize('tree, proof', valid_audit_proofs)
def test_true_audit_verify_proof(tree, proof):
    assert proof.verify(target=tree.get_root_hash())


# Consistency proof verification

trees_and_subtrees = []

for tree in trees:
    for sublength in range(1, tree.length + 1):

        trees_and_subtrees.append(
            (
                tree,
                MerkleTree.init_from_records(
                    *['%d-th record' % _ for _ in range(sublength)],
                    config=tree.get_config())
            )
        )

false_consistency_proofs = []
valid_consistency_proofs = []

for (tree, subtree) in trees_and_subtrees:
    false_consistency_proofs.append(
        (
            tree,
            tree.generate_consistency_proof(
                b'anything except for the right hash value')
        )
    )

    valid_consistency_proofs.append(
        (
            tree,
            tree.generate_consistency_proof(subtree.get_root_hash())
        )
    )


@pytest.mark.parametrize('tree, proof', false_consistency_proofs)
def test_false_consistency_verify_proof(tree, proof):
    with pytest.raises(InvalidProof):
        proof.verify(target=tree.get_root_hash())


@pytest.mark.parametrize('tree, proof', valid_consistency_proofs)
def test_true_consistency_verify_proof(tree, proof):
    assert proof.verify(target=tree.get_root_hash())
