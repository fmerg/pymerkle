"""
Tests the .generate_audit_proof(), .generate_consistency_proof() methods
"""

import pytest

from pymerkle import MerkleTree
from pymerkle.core.hashing import SUPPORTED_HASH_TYPES
from tests.conftest import SUPPORTED_ENCODINGS


# Trees setup

MAX_LENGTH = 4
trees = []
for raw_bytes in (True, False):
    for security in (True, False):
        for length in range(0, MAX_LENGTH + 1):
            for hash_type in SUPPORTED_HASH_TYPES:
                for encoding in SUPPORTED_ENCODINGS:
                    trees.append(
                        MerkleTree(
                            *['%d-th record' % _ for _ in range(length)],
                            hash_type=hash_type,
                            encoding=encoding,
                            raw_bytes=raw_bytes,
                            security=security
                        )
                    )


tree__wrong_arg = []
tree_arg = []

for tree in trees:

    tree__wrong_arg.append(
        (
            tree,
            b'anything that has not been recorded'
        )
    )

    for index in range(tree.length):
        tree_arg.append(
            (
                tree,
                tree.hash('%d-th record' % index)
            )
        )


@pytest.mark.parametrize("tree, arg", tree__wrong_arg)
def test_empty_generate_audit_proof(tree, arg):
    proof = tree.generate_audit_proof(arg)

    assert proof.__dict__ == {
        'header': {
            'uuid': proof.header['uuid'],
            'timestamp': proof.header['timestamp'],
            'created_at': proof.header['created_at'],
            'provider': tree.uuid,
            'hash_type': tree.hash_type,
            'encoding': tree.encoding,
            'raw_bytes': tree.raw_bytes,
            'security': tree.security,
            'commitment': proof.header['commitment'],
            'status': None
        },
        'body': {
            'offset': -1,
            'path': ()
        }
    }


@pytest.mark.parametrize("tree, arg", tree_arg)
def test_non_empty_generate_audit_proof(tree, arg):
    proof = tree.generate_audit_proof(arg)

    assert proof.__dict__ == {
        'header': {
            'uuid': proof.header['uuid'],
            'timestamp': proof.header['timestamp'],
            'created_at': proof.header['created_at'],
            'provider': tree.uuid,
            'hash_type': tree.hash_type,
            'encoding': tree.encoding,
            'raw_bytes': tree.raw_bytes,
            'security': tree.security,
            'commitment': proof.header['commitment'],
            'status': None
        },
        'body': {
            'offset': proof.body['offset'],
            'path': proof.body['path']
        }
    }


# Consistency proof

trees_and_subtrees = []

for tree in trees:
    for sublength in range(1, tree.length + 1):

        trees_and_subtrees.append(
            (
                tree,
                MerkleTree(
                    *['%d-th record' % _ for _ in range(sublength)],
                    hash_type=tree.hash_type,
                    encoding=tree.encoding,
                    raw_bytes=tree.raw_bytes,
                    security=tree.security
                )
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
    """
    Tests that the generated non-empty consistency proof is as expected
    """
    proof = tree.generate_consistency_proof(subhash)

    assert proof.__dict__ == {
        'header': {
            'uuid': proof.header['uuid'],
            'timestamp': proof.header['timestamp'],
            'created_at': proof.header['created_at'],
            'provider': tree.uuid,
            'hash_type': tree.hash_type,
            'encoding': tree.encoding,
            'raw_bytes': tree.raw_bytes,
            'security': tree.security,
            'commitment': proof.header['commitment'],
            'status': None
        },
        'body': {
            'offset': proof.body['offset'],
            'path': proof.body['path']
        }
    }


@pytest.mark.parametrize("tree, subhash", tree__subhash)
def test_empty_generate_consistency_proof_with_wrong_subhash(tree, subhash):
    """
    Tests that the generated empty consistency proof, requested
    for a wrong hash, is as expected
    """
    proof = tree.generate_consistency_proof(subhash, sublength)

    assert proof.__dict__ == {
        'header': {
            'uuid': proof.header['uuid'],
            'timestamp': proof.header['timestamp'],
            'created_at': proof.header['created_at'],
            'provider': tree.uuid,
            'hash_type': tree.hash_type,
            'encoding': tree.encoding,
            'raw_bytes': tree.raw_bytes,
            'security': tree.security,
            'commitment': proof.header['commitment'],
            'status': None
        },
        'body': {
            'offset': proof.body['offset'],
            'path': proof.body['path']
        }
    }


@pytest.mark.parametrize("tree, subhash", tree__subhash)
def test_empty_generate_consistency_proof_with_wrong_subhash(tree, subhash):
    """
    Tests that the generated empty consistency proof, requested
    for a wrong sublength, is as expected
    """
    proof = tree.generate_consistency_proof(subhash, sublength)

    assert proof.__dict__ == {
        'header': {
            'uuid': proof.header['uuid'],
            'timestamp': proof.header['timestamp'],
            'created_at': proof.header['created_at'],
            'provider': tree.uuid,
            'hash_type': tree.hash_type,
            'encoding': tree.encoding,
            'raw_bytes': tree.raw_bytes,
            'security': tree.security,
            'commitment': proof.header['commitment'],
            'status': None
        },
        'body': {
            'offset': proof.body['offset'],
            'path': proof.body['path']
        }
    }
