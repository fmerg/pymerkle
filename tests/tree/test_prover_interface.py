"""
Tests the .merkleProof(), .auditProof(), .consistencyProof() methods
"""

import pytest

from pymerkle import MerkleTree
from pymerkle.hashing import HASH_TYPES
from pymerkle.exceptions import InvalidChallengeError, InvalidChallengeError
from tests.config import ENCODINGS


# merkleProof (uniform interface)

tree = MerkleTree(*[f'{i}-th record' for i in range(666)])

hash_func = tree.hash
audit_challenge_1 = {'checksum': hash_func('100-th record')}
audit_challenge_2 = {'checksum': hash_func(b'anything non recorded...')}

@pytest.mark.parametrize('challenge', [audit_challenge_1, audit_challenge_2])
def test_audit_merkleProof(challenge):
    merkle_proof = tree.merkleProof(challenge)
    commitment = merkle_proof.header['commitment']
    audit_proof = tree.auditProof(challenge['checksum'])
    assert commitment == tree.rootHash and merkle_proof.body == audit_proof.body

cons_challenge_1 = {'subhash': tree.rootHash}
cons_challenge_2 = {'subhash': b'anything else...'}

for i in range(1000):
    tree.encryptRecord(f'{i}-th record')

@pytest.mark.parametrize('challenge', [cons_challenge_1, cons_challenge_2])
def test_consistency_merkleProof(challenge):
    subhash = challenge['subhash']
    consistency_proof = tree.consistencyProof(subhash)
    merkle_proof = tree.merkleProof(challenge)
    commitment = merkle_proof.header['commitment']

    assert commitment == tree.rootHash and merkle_proof.body == consistency_proof.body


__invalid_challenges = [
    {},
    {
        'checksum': 100                      # anything that is not bytes or str
    },
    {
        'checksum': hash_func('100-th record'),
        'extra key': 'extra_value'
    },
    {
        'subhash': 100,                      # anything that is not bytes or str
    },
    {
        'subhash': tree.rootHash,
        'extra key': 'extra value'
    },
    {
        'key_1': 0, 'key_2': 1, 'key_3': 2
    },
]

@pytest.mark.parametrize('challenge', __invalid_challenges)
def test_merkleProof_with_invalid_challenges(challenge):
    with pytest.raises(InvalidChallengeError):
        tree.merkleProof(challenge)


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
        100# 'anything that is not of type... bytes'
    ),
    (
        MerkleTree(),
        {
            'a': 200,#'anything that is not...',
            'b': 300#... of type bytes'
        },
    ),
]

@pytest.mark.parametrize("tree, arg", __invalid_audit_proof_requests)
def test_audit_InvalidChallengeError(tree, arg):
    with pytest.raises(InvalidChallengeError):
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
            'provider': tree.uuid,
            'hash_type': tree.hash_type,
            'encoding': tree.encoding,
            'raw_bytes': tree.raw_bytes,
            'security': tree.security,
            'commitment': audit_proof.header['commitment'],
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
            'provider': tree.uuid,
            'hash_type': tree.hash_type,
            'encoding': tree.encoding,
            'raw_bytes': tree.raw_bytes,
            'security': tree.security,
            'commitment': audit_proof.header['commitment'],
            'status': None
        },
        'body': {
            'proof_index': audit_proof.body['proof_index'],
            'proof_path': audit_proof.body['proof_path']
        }
    }


# Consistency proof

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


__invalid_consistency_proof_requests = []
__tree__subhash = []

for (tree, subtree) in __trees_and_subtrees:

        __invalid_consistency_proof_requests.append(
            (
                tree,
                100,                            # Invalid type for `subhash`
            ),
        )

        __tree__subhash.append(
            (
                tree,
                subtree.rootHash,
            )
        )


@pytest.mark.parametrize("tree, subhash", __invalid_consistency_proof_requests)
def test_consistency_InvalidChallengeError(tree, subhash):
    """
    """
    with pytest.raises(InvalidChallengeError):
        tree.consistencyProof(subhash)


@pytest.mark.parametrize("tree, subhash", __tree__subhash)
def test_non_empty_consistencyProof(tree, subhash):
    """
    Tests that the generated non-empty consistency proof is as expected
    """
    consistency_proof = tree.consistencyProof(subhash)

    assert consistency_proof.__dict__ == {
        'header': {
            'uuid': consistency_proof.header['uuid'],
            'timestamp': consistency_proof.header['timestamp'],
            'creation_moment': consistency_proof.header['creation_moment'],
            'provider': tree.uuid,
            'hash_type': tree.hash_type,
            'encoding': tree.encoding,
            'raw_bytes': tree.raw_bytes,
            'security': tree.security,
            'commitment': consistency_proof.header['commitment'],
            'status': None
        },
        'body': {
            'proof_index': consistency_proof.body['proof_index'],
            'proof_path': consistency_proof.body['proof_path']
        }
    }

@pytest.mark.parametrize("tree, subhash", __tree__subhash)
def test_empty_consistencyProof_with_wrong_subhash(tree, subhash):
    """
    Tests that the generated empty consistency proof, requested
    for a wrong hash, is as expected
    """
    consistency_proof = tree.consistencyProof(subhash, sublength)

    assert consistency_proof.__dict__ == {
        'header': {
            'uuid': consistency_proof.header['uuid'],
            'timestamp': consistency_proof.header['timestamp'],
            'creation_moment': consistency_proof.header['creation_moment'],
            'provider': tree.uuid,
            'hash_type': tree.hash_type,
            'encoding': tree.encoding,
            'raw_bytes': tree.raw_bytes,
            'security': tree.security,
            'commitment': consistency_proof.header['commitment'],
            'status': None
        },
        'body': {
            'proof_index': consistency_proof.body['proof_index'],
            'proof_path': consistency_proof.body['proof_path']
        }
    }

@pytest.mark.parametrize("tree, subhash", __tree__subhash)
def test_empty_consistencyProof_with_wrong_subhash(tree, subhash):
    """
    Tests that the generated empty consistency proof, requested
    for a wrong sublength, is as expected
    """
    consistency_proof = tree.consistencyProof(subhash, sublength)

    assert consistency_proof.__dict__ == {
        'header': {
            'uuid': consistency_proof.header['uuid'],
            'timestamp': consistency_proof.header['timestamp'],
            'creation_moment': consistency_proof.header['creation_moment'],
            'provider': tree.uuid,
            'hash_type': tree.hash_type,
            'encoding': tree.encoding,
            'raw_bytes': tree.raw_bytes,
            'security': tree.security,
            'commitment': consistency_proof.header['commitment'],
            'status': None
        },
        'body': {
            'proof_index': consistency_proof.body['proof_index'],
            'proof_path': consistency_proof.body['proof_path']
        }
    }


# Test string conversion to bytes

tree = MerkleTree(*[f'{i}-th record' for i in range(666)])
hexstring = '15d02997b9e32d81ffefa8fad54a252a6e5303f846140e544c008455e64660ec'

def test_conversion_at_auditProof():
    proof_1 = tree.auditProof(hexstring)
    proof_2 = tree.auditProof(hexstring.encode())
    assert proof_1.body['proof_path'] == proof_2.body['proof_path']

subhash = tree.rootHash
for i in range(1000):
    tree.update(f'{i}-th record')

def test_conversion_at_consistencyProof():
    consistencyProof = tree.consistencyProof
    proof_1 = consistencyProof(subhash=subhash)
    proof_2 = consistencyProof(subhash=subhash.decode())
    assert proof_1.body['proof_path'] == proof_2.body['proof_path']
