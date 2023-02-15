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
    tree = MerkleTree.init_from_entries(
        *[f'{i}-th entry' for i in range(666)])
    proof = tree.prove_inclusion(tree.hash_entry('100-th entry'))
    assert proof.verify() is proof.verify(target=proof.commitment)


# Trees setup


max_length = 4
trees = []
for config in all_configs(option):
    for length in range(1, max_length + 1):
        tree = MerkleTree.init_from_entries(
            *['%d-th entry' % i for i in range(length)],
            config=config)
        trees.append(tree)


# Inclusion proof verification

false_inclusion_proofs = []
valid_inclusion_proofs = []

for tree in trees:
    false_inclusion_proofs.append(
        (
            tree,
            tree.prove_inclusion(b'anything that has not been appended')
        )
    )

    for index in range(0, tree.length):
        valid_inclusion_proofs.append(
            (
                tree,
                tree.prove_inclusion(tree.hash_entry('%d-th entry' % index))
            )
        )


@pytest.mark.parametrize('tree, proof', false_inclusion_proofs)
def test_false_inclusion_verify_proof(tree, proof):
    with pytest.raises(InvalidProof):
        proof.verify(target=tree.get_root_hash())


@pytest.mark.parametrize('tree, proof', valid_inclusion_proofs)
def test_true_inclusion_verify_proof(tree, proof):
    assert proof.verify(target=tree.get_root_hash())


# Consistency proof verification

trees_and_subtrees = []

for tree in trees:
    for sublength in range(1, tree.length + 1):

        trees_and_subtrees.append(
            (
                tree,
                MerkleTree.init_from_entries(
                    *['%d-th entry' % _ for _ in range(sublength)],
                    config=tree.get_config())
            )
        )

false_consistency_proofs = []
valid_consistency_proofs = []

for (tree, subtree) in trees_and_subtrees:
    false_consistency_proofs.append(
        (
            tree,
            tree.prove_consistency(
                b'anything except for the right hash value')
        )
    )

    valid_consistency_proofs.append(
        (
            tree,
            tree.prove_consistency(subtree.get_root_hash())
        )
    )


@pytest.mark.parametrize('tree, proof', false_consistency_proofs)
def test_false_consistency_verify_proof(tree, proof):
    with pytest.raises(InvalidProof):
        proof.verify(target=tree.get_root_hash())


@pytest.mark.parametrize('tree, proof', valid_consistency_proofs)
def test_true_consistency_verify_proof(tree, proof):
    assert proof.verify(target=tree.get_root_hash())
