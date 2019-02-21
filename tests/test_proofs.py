import pytest
from pymerkle import MerkleTree, validateProof
from pymerkle.proof import Proof
import json

# Generate proofs from a one-thousand leaves Merkle-tree
tree = MerkleTree(*(bytes('{}-th record'.format(i), 'utf-8')
                    for i in range(0, 1000)))
p = tree.auditProof(666)  # Genuine index-based proof
q = tree.auditProof(1000)  # Empty index-based proof

# ------------------- Check replicates in all possible ways -------------------

p_1 = Proof(from_json=p.JSONstring())
p_2 = Proof(from_dict=json.loads(p.JSONstring()))
q_1 = Proof(from_json=q.JSONstring())
q_2 = Proof(from_dict=json.loads(q.JSONstring()))


@pytest.mark.parametrize('replicate', (p_1, p_2))
def test_p_replicates_via_serialization(replicate):
    assert p.serialize() == replicate.serialize()


@pytest.mark.parametrize('replicate', (q_1, q_2))
def test_q_replicates_via_serialization(replicate):
    assert q.serialize() == replicate.serialize()

# ----------------------- Check record based generations -----------------


p_3 = tree.auditProof('665-th record')
p_4 = tree.auditProof(b'665-th record')


@pytest.mark.parametrize('r', (p_3, p_4))
def test_record_based_audit_proof(r):
    assert tree.multi_hash(
        p.body['proof_path'],
        p.body['proof_index']) == tree.multi_hash(
        r.body['proof_path'],
        p.body['proof_index'])
