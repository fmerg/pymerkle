import hashlib
import pytest

# Ensure that sha3 is available if a keccak hash function is requested
try:
    import sha3
except ImportError:
    pass

from pymerkle.hasher import ALGORITHMS, KECCAK_ALGORITHMS
from pymerkle.hasher import MerkleHasher


data = b'oculusnonviditnecaurisaudivit'
leaf_prefix = b'\x00'
node_prefix = b'\x01'


def test_hash_buff(config):
    algorithm = config['algorithm']
    security = not config['disable_security']
    h = MerkleHasher(algorithm, security)

    module = sha3 if algorithm in KECCAK_ALGORITHMS else hashlib
    payload = data if not security else (leaf_prefix + data)
    assert h.hash_buff(data) == getattr(module, algorithm)(payload).digest()


def test_hash_pair(config):
    algorithm = config['algorithm']
    security = not config['disable_security']
    h = MerkleHasher(algorithm, security)

    module = sha3 if algorithm in KECCAK_ALGORITHMS else hashlib
    payload = (data + data) if not h.security else (node_prefix + data + data)
    assert h.hash_pair(data, data) == getattr(module, algorithm)(payload).digest()


@pytest.mark.parametrize('algorithm', ALGORITHMS)
def test_algorithm_normalization(algorithm):
    variant = algorithm.upper().replace('_', '-')
    h = MerkleHasher(variant)

    assert h.algorithm == algorithm
    assert h.hash_buff(data) == MerkleHasher(algorithm).hash_buff(data)


def test_unsupported_algorithm():
    with pytest.raises(ValueError):
        MerkleHasher('md5')


def test_hash_fold():
    h = MerkleHasher('sha256')
    d1, d2, d3 = (h.hash_buff(b'%d' % i) for i in range(3))

    assert h.hash_fold([d1]) == d1
    assert h.hash_fold([d1, d2, d3]) == \
        h.hash_pair(d3, h.hash_pair(d2, d1))
