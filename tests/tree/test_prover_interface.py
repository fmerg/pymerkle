"""
Tests the .auditProof() and .consistencyProof() methods
"""

import pytest
from pymerkle import MerkleTree
from pymerkle.hashing import HashMachine, HASH_TYPES
from pymerkle.exceptions import InvalidProofRequest

from tests.config import ENCODINGS


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


# Audit-proof

__invalid_audit_proof_requests = [
    (
        MerkleTree(),
        'anything that is not of type... bytes'
    ),
    (
        MerkleTree(),
        {
            'a': 'anything that is not...',
            'b': '... of type bytes'
        },
    ),
]

@pytest.mark.parametrize("tree, arg", __invalid_audit_proof_requests)
def test_audit_InvalidProofRequest(tree, arg):
    with pytest.raises(InvalidProofRequest):
        tree.auditProof(arg)

__tree__wrong_arg = []
__tree__arg = []

for tree in trees:

    __tree__wrong_arg.append(
        (
            tree,
            b'anything that has not been recorded'
        )
    )

    for index in range(tree.length):
        __tree__arg.append(
                (
                    tree,
                    tree.hash('%d-th record' % index)
                )
            )

@pytest.mark.parametrize("tree, arg", __tree__wrong_arg)
def test_empty_auditProof(tree, arg):
    audit_proof = tree.auditProof(arg)

    assert audit_proof.__dict__ == {
        'header': {
            'uuid': audit_proof.header['uuid'],
            'timestamp': audit_proof.header['timestamp'],
            'creation_moment': audit_proof.header['creation_moment'],
            'generation': False,
            'provider': tree.uuid,
            'hash_type': tree.hash_type,
            'encoding': tree.encoding,
            'raw_bytes': tree.raw_bytes,
            'security': tree.security,
            'status': None
        },
        'body': {
            'proof_index': -1,
            'proof_path': ()
        }
    }

@pytest.mark.parametrize("tree, arg", __tree__arg)
def test_non_empty_auditProof(tree, arg):
    audit_proof = tree.auditProof(arg)

    assert audit_proof.__dict__ == {
        'header': {
            'uuid': audit_proof.header['uuid'],
            'timestamp': audit_proof.header['timestamp'],
            'creation_moment': audit_proof.header['creation_moment'],
            'generation': True,
            'provider': tree.uuid,
            'hash_type': tree.hash_type,
            'encoding': tree.encoding,
            'raw_bytes': tree.raw_bytes,
            'security': tree.security,
            'status': None
        },
        'body': {
            'proof_index': audit_proof.body['proof_index'],
            'proof_path': audit_proof.body['proof_path']
        }
    }


# Consistency-proof

__trees_and_subtrees = []

for tree in trees:
    for sublength in range(1, tree.length + 1):

        __trees_and_subtrees.append(
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


__invalid_consistency_proof_requests = [
    (
        MerkleTree(),
        b'anything...',
        0,                                                  # Could be any number
    )
]
__tree__subhash__sublength = []
__tree__wrong_hash__sublength = []
__tree__subhash__wrong_sublength = []

for (tree, subtree) in __trees_and_subtrees:

        __invalid_consistency_proof_requests.extend(
            [
                (
                    tree,
                    'any non bytes object',                 # Invalid type for `subhash`
                    subtree.length
                ),
                (
                    tree,
                    subtree.rootHash,
                    'any non int object'                    # Invalid type for `sublength`
                ),
                (
                    tree,
                    subtree.rootHash,
                    0                                       # Zero sublength
                ),
                (
                    tree,
                    subtree.rootHash,
                    -1                                      # Negative sublength
                )
            ]
        )

        __tree__subhash__sublength.append(
            (
                tree,
                subtree.rootHash,
                subtree.length
            )
        )

        __tree__wrong_hash__sublength.append(
            (
                tree,
                bytes('anything except for the correct hash', tree.encoding),
                subtree.length
            )
        )

        __tree__subhash__wrong_sublength.append(
            (
                tree,
                subtree.rootHash,
                subtree.length + 1
            )
        )



@pytest.mark.parametrize("tree, subhash, sublength", __invalid_consistency_proof_requests)
def test_consistency_InvalidProofRequest(tree, subhash, sublength):
    """
    Tests ``InvalidProofRequest`` upon requesting
    a consistency proof with invalid arguments
    """
    with pytest.raises(InvalidProofRequest):
        tree.consistencyProof(subhash, sublength)


@pytest.mark.parametrize("tree, subhash, sublength", __tree__subhash__sublength)
def test_non_empty_consistencyProof(tree, subhash, sublength):
    """
    Tests that the generated non-empty consistency proof is as expected
    """
    consistency_proof = tree.consistencyProof(subhash, sublength)

    assert consistency_proof.__dict__ == {
        'header': {
            'uuid': consistency_proof.header['uuid'],
            'timestamp': consistency_proof.header['timestamp'],
            'creation_moment': consistency_proof.header['creation_moment'],
            'generation': True,
            'provider': tree.uuid,
            'hash_type': tree.hash_type,
            'encoding': tree.encoding,
            'raw_bytes': tree.raw_bytes,
            'security': tree.security,
            'status': None
        },
        'body': {
            'proof_index': consistency_proof.body['proof_index'],
            'proof_path': consistency_proof.body['proof_path']
        }
    }

@pytest.mark.parametrize("tree, subhash, sublength", __tree__subhash__sublength)
def test_empty_consistencyProof_with_wrong_subhash(tree, subhash, sublength):
    """
    Tests that the generated empty consistency-proof, requested
    for a wrong hash, is as expected
    """
    consistency_proof = tree.consistencyProof(subhash, sublength)

    assert consistency_proof.__dict__ == {
        'header': {
            'uuid': consistency_proof.header['uuid'],
            'timestamp': consistency_proof.header['timestamp'],
            'creation_moment': consistency_proof.header['creation_moment'],
            'generation': True,
            'provider': tree.uuid,
            'hash_type': tree.hash_type,
            'encoding': tree.encoding,
            'raw_bytes': tree.raw_bytes,
            'security': tree.security,
            'status': None
        },
        'body': {
            'proof_index': consistency_proof.body['proof_index'],
            'proof_path': consistency_proof.body['proof_path']
        }
    }

@pytest.mark.parametrize("tree, subhash, sublength", __tree__subhash__sublength)
def test_empty_consistencyProof_with_wrong_subhash(tree, subhash, sublength):
    """
    Tests that the generated empty consistency-proof, requested
    for a wrong sublength, is as expected
    """
    consistency_proof = tree.consistencyProof(subhash, sublength)

    assert consistency_proof.__dict__ == {
        'header': {
            'uuid': consistency_proof.header['uuid'],
            'timestamp': consistency_proof.header['timestamp'],
            'creation_moment': consistency_proof.header['creation_moment'],
            'generation': True,
            'provider': tree.uuid,
            'hash_type': tree.hash_type,
            'encoding': tree.encoding,
            'raw_bytes': tree.raw_bytes,
            'security': tree.security,
            'status': None
        },
        'body': {
            'proof_index': consistency_proof.body['proof_index'],
            'proof_path': consistency_proof.body['proof_path']
        }
    }
