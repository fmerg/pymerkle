import pytest
import hashlib
from pymerkle.hashing import HashEngine, UnsupportedParameter
from pymerkle.constants import ALGORITHMS
from tests.conftest import option, all_configs


record = 'oculusnonviditnecaurisaudivit'


@pytest.mark.parametrize('config', all_configs(option))
def test_single_string_hash(config):
    engine = HashEngine(**config)

    security = engine.security
    algorithm = engine.algorithm
    encoding = engine.encoding

    prefx00 = '\x00'.encode(encoding)
    data = record.encode(encoding)

    if security:
        assert engine.hash_entry(record) == bytes(
            getattr(hashlib, algorithm)(
                prefx00 +
                data
            ).hexdigest(),
            encoding
        )
    else:
        assert engine.hash_entry(record) == bytes(
            getattr(hashlib, algorithm)(data).hexdigest(),
            encoding
        )


@pytest.mark.parametrize('config', all_configs(option))
def test_single_bytes_hash(config):
    engine = HashEngine(**config)

    security = engine.security
    algorithm = engine.algorithm
    encoding = engine.encoding

    prefx00 = '\x00'.encode(encoding)
    data = record.encode(encoding)

    if security:
        assert engine.hash_entry(data) == bytes(
            getattr(hashlib, algorithm)(
                bytes('\x00', encoding) +
                data
            ).hexdigest(),
            encoding
        )
    else:
        assert engine.hash_entry(data) == bytes(
            getattr(hashlib, algorithm)(data).hexdigest(),
            encoding
        )


@pytest.mark.parametrize('config', all_configs(option))
def test_double_bytes_hash(config):
    engine = HashEngine(**config)

    security = engine.security
    algorithm = engine.algorithm
    encoding = engine.encoding

    prefx00 = '\x00'.encode(encoding)
    prefx01 = '\x01'.encode(encoding)
    data = record.encode(encoding)

    if security:
        assert engine.hash_pair(
            data,
            data) == bytes(
            getattr(hashlib, algorithm)(
                prefx01 +
                data +
                prefx01 +
                data
            ).hexdigest(),
            encoding
        )
    else:
        assert engine.hash_pair(
            data,
            data) == bytes(
                getattr(hashlib, algorithm)(
                    data +
                    data
                ).hexdigest(),
                encoding
        )
