"""Tests the .auditProof() and .consistencyProof() methods of the MerkleTree class
"""

import pytest
from pymerkle import MerkleTree, hashing
from pymerkle.exceptions import InvalidProofRequest

# -------------------------------- Common setup --------------------------------

HASH_TYPES = hashing.HASH_TYPES
ENCODINGS  = hashing.ENCODINGS

MAX_LENGTH = 4

trees = []

for security in (True, False):
    for _length in range(0, MAX_LENGTH + 1):
        for hash_type in HASH_TYPES:
            for encoding in ENCODINGS:

                trees.append(
                    MerkleTree(
                        *['%d-th record' %i for i in range(_length)],
                        hash_type=hash_type,
                        encoding=encoding,
                        security=security
                    )
                )


# ---------------------------- Audit-proof testing ----------------------------


invalid_audit_proof_requests = [
    (
        MerkleTree(),
        [
            'anything...',
            '... that is not int, str, bytes or bytearray'
        ]
    ),
    (
        MerkleTree(),
        {
            'a': 'anything...',
            'b': '... that is not int, str, bytes or bytearray'
        },
    ),
]

@pytest.mark.parametrize("_tree, _arg", invalid_audit_proof_requests)
def test_audit_InvalidProofRequest(_tree, _arg):
    with pytest.raises(InvalidProofRequest):
        _tree.auditProof(_arg)

_tree_wrong_arg                = []
_tree__arg                     = []

for _tree in trees:

    _tree_wrong_arg.extend(
        [
            (
                _tree,
                -1                                      # Audit-proof requested upon negative index
            ),
            (
                _tree,
                _tree.length                            # Audit-proof requested upon index exceeding current length
            ),
            (
                _tree,
                'anything that has not been recorded'   # Audit-proof requested upon non encrypted record
            )
        ]
    )

    for _index in range(0, _tree.length):
        _tree__arg.extend(
            [
                (
                    _tree,
                    _index                              # Index based proof
                ),
                (
                    _tree,
                    '%d-th record' % _index             # String based proof
                ),
                (
                    _tree,
                    bytes(
                        '%d-th record' % _index,
                        _tree.encoding
                    )                                 # Bytes based proof
                ),
                (
                    _tree,
                    bytearray(
                        '%d-th record' % _index,
                        _tree.encoding
                    )                                 # Bytearray based proof
                )
            ]
        )

@pytest.mark.parametrize("_tree, _arg", _tree_wrong_arg)
def test_empty_auditProof(_tree, _arg):

    _audit_proof = _tree.auditProof(_arg)

    assert _audit_proof.__dict__ == {
        'header': {
            'uuid': _audit_proof.header['uuid'],
            'timestamp': _audit_proof.header['timestamp'],
            'creation_moment': _audit_proof.header['creation_moment'],
            'generation': False,
            'provider': _tree.uuid,
            'hash_type': _tree.hash_type,
            'encoding': _tree.encoding,
            'security': _tree.security,
            'status': None
        },
        'body': {
            'proof_index': -1,
            'proof_path': ()
        }
    }

@pytest.mark.parametrize("_tree, _arg", _tree__arg)
def test_non_empty_auditProof(_tree, _arg):

    _audit_proof = _tree.auditProof(_arg)

    assert _audit_proof.__dict__ == {
        'header': {
            'uuid': _audit_proof.header['uuid'],
            'timestamp': _audit_proof.header['timestamp'],
            'creation_moment': _audit_proof.header['creation_moment'],
            'generation': True,
            'provider': _tree.uuid,
            'hash_type': _tree.hash_type,
            'encoding': _tree.encoding,
            'security': _tree.security,
            'status': None
        },
        'body': {
            'proof_index': _audit_proof.body['proof_index'],
            'proof_path': _audit_proof.body['proof_path']
        }
    }


# ------------------------- Consistency-proof testing -------------------------


trees_and_subtrees = []

for _tree in trees:
    for _sublength in range(1, _tree.length + 1):

        trees_and_subtrees.append(
            (
                _tree,
                MerkleTree(
                    *['%d-th record' %_ for _ in range(_sublength)],
                    hash_type=_tree.hash_type,
                    encoding=_tree.encoding,
                    security=_tree.security
                )
            )
        )


_invalid_consistency_proof_requests = [
    (
        MerkleTree(),
        b'anything...',
        0,                                                  # Could be any number
    )
]
_tree__old_hash__sublength          = []
_tree__wrong_hash__sublength        = []
_tree__old_hash__wrong_sublength    = []

for (_tree, _subtree) in trees_and_subtrees:

        _invalid_consistency_proof_requests.extend(
            [
                (
                    _tree,
                    'any non bytes object',                 # Invalid type for `old_hash`
                    _subtree.length
                ),
                (
                    _tree,
                    _subtree.rootHash,
                    'any non int object'                    # Invalid type for `sublength`
                ),
                (
                    _tree,
                    _subtree.rootHash,
                    0                                       # Zero sublength
                ),
                (
                    _tree,
                    _subtree.rootHash,
                    -1                                      # Negative sublength
                )
            ]
        )

        _tree__old_hash__sublength.append(
            (
                _tree,
                _subtree.rootHash,
                _subtree.length
            )
        )

        _tree__wrong_hash__sublength.append(
            (
                _tree,
                b'anything except for the rigth hash',
                _subtree.length
            )
        )

        _tree__old_hash__wrong_sublength.append(
            (
                _tree,
                _subtree.rootHash,
                _subtree.length + 1
            )
        )



@pytest.mark.parametrize("_tree, _old_hash, _sublength", _invalid_consistency_proof_requests)
def test_consistency_InvalidProofRequest(_tree, _old_hash, _sublength):
    """Tests that InvalidProofRequest is raised when a consistency proof is requested
    with invalid arguments
    """
    with pytest.raises(InvalidProofRequest):
        _tree.consistencyProof(_old_hash, _sublength)


@pytest.mark.parametrize("_tree, _old_hash, _sublength", _tree__old_hash__sublength)
def test_non_empty_consistencyProof(_tree, _old_hash, _sublength):
    """Tests that the generated non-empty consistency proof is as expected
    """

    _consistency_proof = _tree.consistencyProof(_old_hash, _sublength)

    assert _consistency_proof.__dict__ == {
        'header': {
            'uuid': _consistency_proof.header['uuid'],
            'timestamp': _consistency_proof.header['timestamp'],
            'creation_moment': _consistency_proof.header['creation_moment'],
            'generation': True,
            'provider': _tree.uuid,
            'hash_type': _tree.hash_type,
            'encoding': _tree.encoding,
            'security': _tree.security,
            'status': None
        },
        'body': {
            'proof_index': _consistency_proof.body['proof_index'],
            'proof_path': _consistency_proof.body['proof_path']
        }
    }

@pytest.mark.parametrize("_tree, _old_hash, _sublength", _tree__old_hash__sublength)
def test_empty_consistencyProof_with_wrong_old_hash(_tree, _old_hash, _sublength):
    """Tests that the generated empty consistency-proof, requested for a wrong hash,
    is as expected
    """

    _consistency_proof = _tree.consistencyProof(_old_hash, _sublength)

    assert _consistency_proof.__dict__ == {
        'header': {
            'uuid': _consistency_proof.header['uuid'],
            'timestamp': _consistency_proof.header['timestamp'],
            'creation_moment': _consistency_proof.header['creation_moment'],
            'generation': True,
            'provider': _tree.uuid,
            'hash_type': _tree.hash_type,
            'encoding': _tree.encoding,
            'security': _tree.security,
            'status': None
        },
        'body': {
            'proof_index': _consistency_proof.body['proof_index'],
            'proof_path': _consistency_proof.body['proof_path']
        }
    }

@pytest.mark.parametrize("_tree, _old_hash, _sublength", _tree__old_hash__sublength)
def test_empty_consistencyProof_with_wrong_old_hash(_tree, _old_hash, _sublength):
    """Tests that the generated empty consistency-proof, requested for a wrong sublength,
    is as expected
    """

    _consistency_proof = _tree.consistencyProof(_old_hash, _sublength)

    assert _consistency_proof.__dict__ == {
        'header': {
            'uuid': _consistency_proof.header['uuid'],
            'timestamp': _consistency_proof.header['timestamp'],
            'creation_moment': _consistency_proof.header['creation_moment'],
            'generation': True,
            'provider': _tree.uuid,
            'hash_type': _tree.hash_type,
            'encoding': _tree.encoding,
            'security': _tree.security,
            'status': None
        },
        'body': {
            'proof_index': _consistency_proof.body['proof_index'],
            'proof_path': _consistency_proof.body['proof_path']
        }
    }
