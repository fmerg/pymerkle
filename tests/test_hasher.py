import pytest
import hashlib
from pymerkle.hasher import MerkleHasher
from pymerkle.constants import ALGORITHMS
from tests.conftest import option, all_configs


data = b'oculusnonviditnecaurisaudivit'

prefx00 = b'\x00'
prefx01 = b'\x01'


@pytest.mark.parametrize('config', all_configs(option))
def test_hash_entry(config):
    h = MerkleHasher(**config)

    if h.security:
        assert h.hash_entry(data) == getattr(hashlib, h.algorithm)(
            prefx00 + data).digest()
    else:
        assert h.hash_entry(data) == getattr(hashlib, h.algorithm)(
            data).digest()


@pytest.mark.parametrize('config', all_configs(option))
def test_hash_nodes(config):
    h = MerkleHasher(**config)

    if h.security:
        assert h.hash_nodes(data, data) == getattr(hashlib, h.algorithm)(
            prefx01 + data + data).digest()
    else:
        assert h.hash_nodes(data, data) == getattr(hashlib, h.algorithm)(
            data + data).digest()
