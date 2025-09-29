import hashlib
import pytest

try:
    import sha3
except ImportError:
    pass

try:
    import blake3
except ImportError:
    blake3 = None

from pymerkle.hasher import MerkleHasher
from tests.conftest import option, all_configs


data = b'oculusnonviditnecaurisaudivit'
prefx00 = b'\x00'
prefx01 = b'\x01'


@pytest.mark.parametrize('config', all_configs(option))
def test_hash_buff(config):
    algorithm = config['algorithm']
    security = not config['disable_security']
    h = MerkleHasher(algorithm, security)

    if algorithm.startswith('keccak'):
        module = sha3
    elif algorithm == 'blake3' and blake3 is not None:
        module = blake3
    else:
        module = hashlib
    payload = data if not security else (prefx00 + data)
    assert h.hash_buff(data) == getattr(module, algorithm)(payload).digest()


@pytest.mark.parametrize('config', all_configs(option))
def test_hash_pair(config):
    algorithm = config['algorithm']
    security = not config['disable_security']
    h = MerkleHasher(algorithm, security)

    if algorithm.startswith('keccak'):
        module = sha3
    elif algorithm == 'blake3' and blake3 is not None:
        module = blake3
    else:
        module = hashlib
    payload = (data + data) if not h.security else (prefx01 + data + data)
    assert h.hash_pair(data, data) == getattr(module, algorithm)(payload).digest()
