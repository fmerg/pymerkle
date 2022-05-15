"""
Tests proof generation methods
"""

import pytest

from pymerkle import MerkleTree
from pymerkle.hashing import SUPPORTED_HASH_TYPES
from tests.conftest import SUPPORTED_ENCODINGS


# Trees setup

MAX_LENGTH = 4
trees = []
for security in (True, False):
    for length in range(0, MAX_LENGTH + 1):
        for hash_type in SUPPORTED_HASH_TYPES:
            for encoding in SUPPORTED_ENCODINGS:
                config = {'hash_type': hash_type, 'encoding': encoding,
                          'security': security}
                tree = MerkleTree.init_from_records(
                    *['%d-th record' % _ for _ in range(length)],
                    config=config)
                trees.append(tree)


tree__wrong_arg = []
tree_arg = []

for tree in trees:

    tree__wrong_arg.append(
        (
            tree,
            b'anything that has not been recorded'
        )
    )

    for i in range(tree.length):
        tree_arg.append(
            (
                tree,
                tree.hash('%d-th record' % i)
            )
        )


@pytest.mark.parametrize("tree, arg", tree__wrong_arg)
def test_empty_generate_audit_proof(tree, arg):
    proof = tree.generate_audit_proof(arg)

    assert proof.__dict__ == {
        'uuid': proof.uuid,
        'timestamp': proof.timestamp,
        'created_at': proof.created_at,
        'provider': tree.uuid,
        'hash_type': tree.hash_type,
        'encoding': tree.encoding,
        'security': tree.security,
        'commitment': proof.commitment,
        'status': None,
        'offset': -1,
        'path': [],
    }


@pytest.mark.parametrize("tree, arg", tree_arg)
def test_non_empty_generate_audit_proof(tree, arg):
    proof = tree.generate_audit_proof(arg)

    assert proof.__dict__ == {
        'uuid': proof.uuid,
        'timestamp': proof.timestamp,
        'created_at': proof.created_at,
        'provider': tree.uuid,
        'hash_type': tree.hash_type,
        'encoding': tree.encoding,
        'security': tree.security,
        'commitment': proof.commitment,
        'status': None,
        'offset': proof.offset,
        'path': proof.path,
    }


# Consistency proof

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


tree__subhash = []

for (tree, subtree) in trees_and_subtrees:

    tree__subhash.append(
        (
            tree,
            subtree.root_hash,
        )
    )


@pytest.mark.parametrize("tree, subhash", tree__subhash)
def test_non_empty_generate_consistency_proof(tree, subhash):
    proof = tree.generate_consistency_proof(subhash)

    assert proof.__dict__ == {
        'uuid': proof.uuid,
        'timestamp': proof.timestamp,
        'created_at': proof.created_at,
        'provider': tree.uuid,
        'hash_type': tree.hash_type,
        'encoding': tree.encoding,
        'security': tree.security,
        'commitment': proof.commitment,
        'status': None,
        'offset': proof.offset,
        'path': proof.path,
    }


@pytest.mark.parametrize("tree, subhash", tree__subhash)
def test_empty_generate_consistency_proof_with_wrong_subhash(tree, subhash):
    proof = tree.generate_consistency_proof(subhash)

    assert proof.__dict__ == {
        'uuid': proof.uuid,
        'timestamp': proof.timestamp,
        'created_at': proof.created_at,
        'provider': tree.uuid,
        'hash_type': tree.hash_type,
        'encoding': tree.encoding,
        'security': tree.security,
        'commitment': proof.commitment,
        'status': None,
        'offset': proof.offset,
        'path': proof.path,
    }


@pytest.mark.parametrize("tree, subhash", tree__subhash)
def test_empty_generate_consistency_proof_with_wrong_subhash(tree, subhash):
    proof = tree.generate_consistency_proof(subhash)

    assert proof.__dict__ == {
        'uuid': proof.uuid,
        'timestamp': proof.timestamp,
        'created_at': proof.created_at,
        'provider': tree.uuid,
        'hash_type': tree.hash_type,
        'encoding': tree.encoding,
        'security': tree.security,
        'commitment': proof.commitment,
        'status': None,
        'offset': proof.offset,
        'path': proof.path,
    }
