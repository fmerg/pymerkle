import pytest
import hashlib
from pymerkle.hasher import MerkleHasher
from pymerkle.constants import ALGORITHMS
from tests.conftest import option, all_configs


record = 'oculusnonviditnecaurisaudivit'


@pytest.mark.parametrize('config', all_configs(option))
def test_hash_entry_string(config):
    h = MerkleHasher(**config)

    security = h.security
    algorithm = h.algorithm
    encoding = h.encoding

    prefx00 = '\x00'.encode(encoding)
    data = record.encode(encoding)

    if security:
        assert h.hash_entry(record) == bytes(
            getattr(hashlib, algorithm)(
                prefx00 +
                data
            ).hexdigest(),
            encoding
        )
    else:
        assert h.hash_entry(record) == bytes(
            getattr(hashlib, algorithm)(data).hexdigest(),
            encoding
        )


@pytest.mark.parametrize('config', all_configs(option))
def test_hash_entry_bytes(config):
    h = MerkleHasher(**config)

    security = h.security
    algorithm = h.algorithm
    encoding = h.encoding

    prefx00 = '\x00'.encode(encoding)
    data = record.encode(encoding)

    if security:
        assert h.hash_entry(data) == bytes(
            getattr(hashlib, algorithm)(
                bytes('\x00', encoding) +
                data
            ).hexdigest(),
            encoding
        )
    else:
        assert h.hash_entry(data) == bytes(
            getattr(hashlib, algorithm)(data).hexdigest(),
            encoding
        )


@pytest.mark.parametrize('config', all_configs(option))
def test_hash_nodes(config):
    h = MerkleHasher(**config)

    security = h.security
    algorithm = h.algorithm
    encoding = h.encoding

    prefx00 = '\x00'.encode(encoding)
    prefx01 = '\x01'.encode(encoding)
    data = record.encode(encoding)

    if security:
        assert h.hash_nodes(
            data,
            data) == bytes(
            getattr(hashlib, algorithm)(
                prefx01 +
                data +
                data
            ).hexdigest(),
            encoding
        )
    else:
        assert h.hash_nodes(
            data,
            data) == bytes(
                getattr(hashlib, algorithm)(
                    data +
                    data
                ).hexdigest(),
                encoding
        )
