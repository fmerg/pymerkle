"""Tests the .validateProof() and .validationReceipt() functions from the validations.py module
"""

import pytest
import os
import json
from pymerkle import MerkleTree, hashing, validateProof, validationReceipt
from pymerkle.validations import Receipt

def test_validationReceipt():

    _tree = MerkleTree(*['%d-th record' % i for i in range(5)])

    _audit_proof = _tree.auditProof(3)
    _receipt = validationReceipt(
        target_hash=_tree.rootHash,
        proof=_audit_proof,
        dirpath=os.path.join(os.path.dirname(__file__), 'receipts')
    )

    _receipt_path = os.path.join(
        os.path.dirname(__file__),
        'receipts',
        '%s.json' % _receipt.header['uuid']
    )

    with open(_receipt_path) as _file:
        _clone = json.load(_file)
        assert _receipt.serialize() == _clone

# -------------------------------- Common setup --------------------------------


HASH_TYPES = hashing.HASH_TYPES
ENCODINGS  = hashing.ENCODINGS

MAX_LENGTH = 4

trees = []

for security in (True, False):
    for _length in range(1, MAX_LENGTH + 1):
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


# --------------------------- Audit-proof validation ---------------------------


_false__audit_proofs = []
_true__audit_proofs  = []

for _tree in trees:

    _false__audit_proofs.extend(
        [
            (
                _tree,
                _tree.auditProof(-1),                                           # Based upon negative index
            ),
            (
                _tree,
                _tree.auditProof(_tree.length),                                 # Based upon index exceeding current length
            ),
            (
                _tree,
                _tree.auditProof('anything that has not been recorded')         # Based upon non encrypted record
            )
        ]
    )

    for _index in range(0, _tree.length):
        _true__audit_proofs.extend(
            [
                (
                    _tree,
                    _tree.auditProof(_index),                                   # Index based proof
                ),
                (
                    _tree,
                    _tree.auditProof('%d-th record' % _index),                  # String based proof
                ),
                (
                    _tree,
                    _tree.auditProof(
                        bytes(
                            '%d-th record' % _index,
                            _tree.encoding
                        )
                    )                                                           # Bytes based proof
                ),
                (
                    _tree,
                    _tree.auditProof(
                        bytearray(
                            '%d-th record' % _index,
                            _tree.encoding
                        )
                    )                                                           # Bytearray based proof
                )
            ]
        )

@pytest.mark.parametrize("_tree, _audit_proof", _false__audit_proofs)
def test_false_audit_validateProof(_tree, _audit_proof):

    assert not validateProof(_tree.rootHash, _audit_proof)

@pytest.mark.parametrize("_tree, _audit_proof", _true__audit_proofs)
def test_true_audit_validateProof(_tree, _audit_proof):

    assert validateProof(_tree.rootHash, _audit_proof)


# ------------------------ Consistency-proof validation ------------------------

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

_false__consistency_proofs = []
_true__consistency_proofs  = []

for (_tree, _subtree) in trees_and_subtrees:

        _false__consistency_proofs.extend(
            [
                (
                    _tree,
                    _tree.consistencyProof(
                        b'anything except for the right hash',
                        _subtree.length
                    )                                                           # Based upon wrong target-hash
                ),
                (
                    _tree,
                    _tree.consistencyProof(
                        _subtree.rootHash,
                        _subtree.length + 1
                    )                                                           # Based upon wrong sublength
                )
            ]
        )

        _true__consistency_proofs.append(
            (
                _tree,
                _tree.consistencyProof(
                    _subtree.rootHash,
                    _subtree.length
                )
            )
        )

@pytest.mark.parametrize("_tree, _consistency_proof", _false__consistency_proofs)
def test_false_consistency_validateProof(_tree, _consistency_proof):

    assert not validateProof(_tree.rootHash, _consistency_proof)

@pytest.mark.parametrize("_tree, _consistency_proof", _true__consistency_proofs)
def test_true_consistency_validateProof(_tree, _consistency_proof):

    assert validateProof(_tree.rootHash, _consistency_proof)
