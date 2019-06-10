import pytest
from pymerkle.nodes import Node, Leaf
from pymerkle.hashing import hash_machine
from pymerkle.serializers import NodeSerializer

# import json

MACHINE = hash_machine()       # prepends security prefices by default
ENCODING = MACHINE.ENCODING     # utf-8
HASH = MACHINE.hash             # SHA256


def test_leaf_construction_with_neither_record_nor_stored_hash():
    """Tests that the Leaf constructor raises `TypeError`
    if neither `record` nor `stored_hash` is provided
    """
    with pytest.raises(TypeError):
        Leaf(hash_function=HASH, encoding=ENCODING)


def test_leaf_construction_with_both_record_and_stored_hash():
    """Tests that the Leaf constructor raises `TypeError`
    if both `record` and `stored_hash` are provided
    """
    with pytest.raises(TypeError):
        Leaf(hash_function=HASH,
             encoding=ENCODING,
             record=b'anything...',
             stored_hash=HASH('whatever...'))


def test_leaf_with_record():
    """Tests leaf construction when `record` is provided
    """
    _leaf = Leaf(hash_function=HASH,
                 encoding=ENCODING,
                 record=b'some record...')

    assert _leaf.__dict__ == {
        'left': None,
        'right': None,
        'child': None,
        'encoding': ENCODING,
        'stored_hash': bytes(
            HASH('some record...').decode(ENCODING),
            ENCODING)}


def test_leaf_with_stored_hash():
    """Tests leaf construction when `stored_hash` is provided
    """
    _leaf = Leaf(
        hash_function=HASH,
        encoding=ENCODING,
        stored_hash='5f4e54b52702884b03c21efc76b7433607fa3b35343b9fd322521c9c1ed633b4')

    assert _leaf.__dict__ == {
        'left': None,
        'right': None,
        'child': None,
        'encoding': ENCODING,
        'stored_hash': bytes(
            '5f4e54b52702884b03c21efc76b7433607fa3b35343b9fd322521c9c1ed633b4',
            ENCODING)}


# @pytest.mark.parametrize('r', (p_3, p_4))
# def test_record_based_audit_proof(r):
#     assert tree.multi_hash(
#         p.body['proof_path'],
#         p.body['proof_index']) == tree.multi_hash(
#         r.body['proof_path'],
#         p.body['proof_index'])
#
# # Generate proofs from a one-thousand leaves Merkle-tree
# tree = MerkleTree(*(bytes('{}-th record'.format(i), 'utf-8')
#                     for i in range(0, 1000)))
# p = tree.auditProof(666)  # Genuine index-based proof
# q = tree.auditProof(1000)  # Empty index-based proof
#
# # ------------------- Check replicates in all possible ways ------------
#
# p_1 = Proof(from_json=p.JSONstring())
# p_2 = Proof(from_dict=json.loads(p.JSONstring()))
# q_1 = Proof(from_json=q.JSONstring())
# q_2 = Proof(from_dict=json.loads(q.JSONstring()))
#
#
# @pytest.mark.parametrize('replicate', (p_1, p_2))
# def test_p_replicates_via_serialization(replicate):
#     assert p.serialize() == replicate.serialize()
#
#
# @pytest.mark.parametrize('replicate', (q_1, q_2))
# def test_q_replicates_via_serialization(replicate):
#     assert q.serialize() == replicate.serialize()
#
# # ----------------------- Check record based generations -----------------
#
#
# p_3 = tree.auditProof('665-th record')
# p_4 = tree.auditProof(b'665-th record')


# @pytest.mark.parametrize('r', (p_3, p_4))
# def test_record_based_audit_proof(r):
#     assert tree.multi_hash(
#         p.body['proof_path'],
#         p.body['proof_index']) == tree.multi_hash(
#         r.body['proof_path'],
#         p.body['proof_index'])
