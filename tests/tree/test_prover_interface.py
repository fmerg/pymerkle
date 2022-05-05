"""
Tests the .generate_audit_proof(), .generate_consistency_proof() methods
"""

import pytest

from pymerkle import MerkleTree
from pymerkle.hashing import HASH_TYPES
from pymerkle.exceptions import InvalidChallengeError, InvalidChallengeError
from tests.conftest import ENCODINGS


# Trees setup

MAX_LENGTH = 4
trees = []
for raw_bytes in (True, False):
    for security in (True, False):
        for length in range(0, MAX_LENGTH + 1):
            for hash_type in HASH_TYPES:
                for encoding in ENCODINGS:
                    trees.append(
                        MerkleTree(
                            *['%d-th record' % _ for _ in range(length)],
                            hash_type=hash_type,
                            encoding=encoding,
                            raw_bytes=raw_bytes,
                            security=security
                        )
                    )


# Audit proof

__invalid_audit_proof_requests = [
    (
        MerkleTree(),
        100  # 'anything that is not of type... bytes'
    ),
    (
        MerkleTree(),
        {
            'a': 200,  # 'anything that is not...',
            'b': 300  # ... of type bytes'
        },
    ),
]


@pytest.mark.parametrize("tree, arg", __invalid_audit_proof_requests)
def test_audit_InvalidChallengeError(tree, arg):
    with pytest.raises(InvalidChallengeError):
        tree.generate_audit_proof(arg)


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
    audit_proof = tree.generate_audit_proof(arg)

    assert audit_proof.__dict__ == {
        'header': {
            'uuid': audit_proof.header['uuid'],
            'timestamp': audit_proof.header['timestamp'],
            'created_at': audit_proof.header['created_at'],
            'provider': tree.uuid,
            'hash_type': tree.hash_type,
            'encoding': tree.encoding,
            'raw_bytes': tree.raw_bytes,
            'security': tree.security,
            'commitment': audit_proof.header['commitment'],
            'status': None
        },
        'body': {
            'offset': -1,
            'path': ()
        }
    }


@pytest.mark.parametrize("tree, arg", tree_arg)
def test_non_empty_generate_audit_proof(tree, arg):
    audit_proof = tree.generate_audit_proof(arg)

    assert audit_proof.__dict__ == {
        'header': {
            'uuid': audit_proof.header['uuid'],
            'timestamp': audit_proof.header['timestamp'],
            'created_at': audit_proof.header['created_at'],
            'provider': tree.uuid,
            'hash_type': tree.hash_type,
            'encoding': tree.encoding,
            'raw_bytes': tree.raw_bytes,
            'security': tree.security,
            'commitment': audit_proof.header['commitment'],
            'status': None
        },
        'body': {
            'offset': audit_proof.body['offset'],
            'path': audit_proof.body['path']
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


__invalid_consistency_proof_requests = []
tree__subhash = []

for (tree, subtree) in trees_and_subtrees:

    __invalid_consistency_proof_requests.append(
        (
            tree,
            100,                            # Invalid type for `subhash`
        ),
    )

    tree__subhash.append(
        (
            tree,
            subtree.root_hash,
        )
    )


@pytest.mark.parametrize("tree, subhash", __invalid_consistency_proof_requests)
def test_consistency_InvalidChallengeError(tree, subhash):
    """
    """
    with pytest.raises(InvalidChallengeError):
        tree.generate_consistency_proof(subhash)


@pytest.mark.parametrize("tree, subhash", tree__subhash)
def test_non_empty_generate_consistency_proof(tree, subhash):
    """
    Tests that the generated non-empty consistency proof is as expected
    """
    consistency_proof = tree.generate_consistency_proof(subhash)

    assert consistency_proof.__dict__ == {
        'header': {
            'uuid': consistency_proof.header['uuid'],
            'timestamp': consistency_proof.header['timestamp'],
            'created_at': consistency_proof.header['created_at'],
            'provider': tree.uuid,
            'hash_type': tree.hash_type,
            'encoding': tree.encoding,
            'raw_bytes': tree.raw_bytes,
            'security': tree.security,
            'commitment': consistency_proof.header['commitment'],
            'status': None
        },
        'body': {
            'offset': consistency_proof.body['offset'],
            'path': consistency_proof.body['path']
        }
    }


@pytest.mark.parametrize("tree, subhash", tree__subhash)
def test_empty_generate_consistency_proof_with_wrong_subhash(tree, subhash):
    """
    Tests that the generated empty consistency proof, requested
    for a wrong hash, is as expected
    """
    consistency_proof = tree.generate_consistency_proof(subhash, sublength)

    assert consistency_proof.__dict__ == {
        'header': {
            'uuid': consistency_proof.header['uuid'],
            'timestamp': consistency_proof.header['timestamp'],
            'created_at': consistency_proof.header['created_at'],
            'provider': tree.uuid,
            'hash_type': tree.hash_type,
            'encoding': tree.encoding,
            'raw_bytes': tree.raw_bytes,
            'security': tree.security,
            'commitment': consistency_proof.header['commitment'],
            'status': None
        },
        'body': {
            'offset': consistency_proof.body['offset'],
            'path': consistency_proof.body['path']
        }
    }


@pytest.mark.parametrize("tree, subhash", tree__subhash)
def test_empty_generate_consistency_proof_with_wrong_subhash(tree, subhash):
    """
    Tests that the generated empty consistency proof, requested
    for a wrong sublength, is as expected
    """
    consistency_proof = tree.generate_consistency_proof(subhash, sublength)

    assert consistency_proof.__dict__ == {
        'header': {
            'uuid': consistency_proof.header['uuid'],
            'timestamp': consistency_proof.header['timestamp'],
            'created_at': consistency_proof.header['created_at'],
            'provider': tree.uuid,
            'hash_type': tree.hash_type,
            'encoding': tree.encoding,
            'raw_bytes': tree.raw_bytes,
            'security': tree.security,
            'commitment': consistency_proof.header['commitment'],
            'status': None
        },
        'body': {
            'offset': consistency_proof.body['offset'],
            'path': consistency_proof.body['path']
        }
    }


# Test string conversion to bytes

tree = MerkleTree(*[f'{i}-th record' for i in range(666)])
hexstring = '15d02997b9e32d81ffefa8fad54a252a6e5303f846140e544c008455e64660ec'


def test_conversion_at_generate_audit_proof():
    proof_1 = tree.generate_audit_proof(hexstring)
    proof_2 = tree.generate_audit_proof(hexstring.encode())
    assert proof_1.body['path'] == proof_2.body['path']


subhash = tree.root_hash
for i in range(1000):
    tree.update(f'{i}-th record')


def test_conversion_at_generate_consistency_proof():
    generate_consistency_proof = tree.generate_consistency_proof
    proof_1 = generate_consistency_proof(subhash=subhash)
    proof_2 = generate_consistency_proof(subhash=subhash.decode())
    assert proof_1.body['path'] == proof_2.body['path']
