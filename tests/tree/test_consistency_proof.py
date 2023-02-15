import pytest
from pymerkle import MerkleTree
from tests.conftest import option, all_configs


max_length = 4
trees = []
for config in all_configs(option):
    for length in range(0, max_length + 1):
        records = ['%d' % _ for _ in range(length)]
        tree = MerkleTree.init_from_records(*records, config=config)
        trees.append(tree)


@pytest.mark.parametrize('tree', trees)
def test_empty_consistency_proof(tree):
    challenge = b'anything that is not previous state'
    proof = tree.prove_consistency(challenge)

    assert proof.__dict__ == {
        'uuid': proof.uuid,
        'timestamp': proof.timestamp,
        'created_at': proof.created_at,
        'algorithm': tree.algorithm,
        'encoding': tree.encoding,
        'security': tree.security,
        'commitment': proof.commitment,
        'offset': proof.offset,
        'path': [],
    }


@pytest.mark.parametrize('tree', trees)
def test_non_empty_consistency_proof(tree):
    for sublength in range(1, tree.length + 1):
        records = ['%d' % _ for _ in range(sublength)]
        subtree = MerkleTree.init_from_records(*records, config=config)

        challenge = subtree.get_root_hash()
        proof = tree.prove_consistency(challenge)

        assert proof.__dict__ == {
            'uuid': proof.uuid,
            'timestamp': proof.timestamp,
            'created_at': proof.created_at,
            'algorithm': tree.algorithm,
            'encoding': tree.encoding,
            'security': tree.security,
            'commitment': proof.commitment,
            'offset': proof.offset,
            'path': proof.path,
        }


