import pytest
from pymerkle import MerkleTree
from tests.conftest import option, all_configs

max_length = 4
trees = []
for config in all_configs(option):
    for length in range(0, max_length + 1):
        entries = ['%d' % _ for _ in range(length)]
        tree = MerkleTree.init_from_entries(*entries, config=config)
        trees.append(tree)


@pytest.mark.parametrize('tree', trees)
def test_empty_inclusion_proof(tree):
    challenge = b'anything that has not been appended'
    proof = tree.prove_inclusion(challenge)

    assert proof.__dict__ == {
        'uuid': proof.uuid,
        'timestamp': proof.timestamp,
        'created_at': proof.created_at,
        'algorithm': tree.algorithm,
        'encoding': tree.encoding,
        'security': tree.security,
        'commitment': proof.commitment,
        'offset': -1,
        'path': [],
    }


@pytest.mark.parametrize('tree', trees)
def test_non_empty_inclusion_proof(tree):
    challenges = []
    for i in range(tree.length):
        challenge = tree.hash_entry('%d' % i)
        proof = tree.prove_inclusion(challenge)

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
