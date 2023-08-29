import pytest
import hashlib
import sha3
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

    module = sha3 if algorithm.startswith('keccak') else hashlib
    payload = data if not security else (prefx00 + data)
    assert h.hash_buff(data) == getattr(module, algorithm)(payload).digest()


@pytest.mark.parametrize('config', all_configs(option))
def test_hash_pair(config):
    algorithm = config['algorithm']
    security = not config['disable_security']
    h = MerkleHasher(algorithm, security)

    module = sha3 if algorithm.startswith('keccak') else hashlib
    payload = (data + data) if not h.security else (prefx01 + data + data)
    assert h.hash_pair(data, data) == getattr(module, algorithm)(payload).digest()
