import pytest
import hashlib
from pymerkle.hashing import HashEngine, ALGORITHMS, \
    EmptyPathException, UnsupportedParameter
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


@pytest.mark.parametrize('config', all_configs(option))
def test_0_elems_hash_path(config):
    engine = HashEngine(**config)

    with pytest.raises(EmptyPathException):
        assert engine.hash_path((), 'anything')


@pytest.mark.parametrize('config', all_configs(option))
def test_1_elems_hash_path(config):
    engine = HashEngine(**config)

    assert engine.hash_path(
        [(+1, engine.hash_entry(record))], 0
    ) == engine.hash_entry(record)


@pytest.mark.parametrize('config', all_configs(option))
def test_2_elems_hash_path(config):
    engine = HashEngine(**config)

    hashf = engine.hash_pair
    hash_path = engine.hash_path
    data = record.encode(engine.encoding)

    if engine.security:
        assert hash_path(
            (
                (
                    +1,
                    data
                ),
                (
                    -1,
                    data
                )
            ),
            0
        ) == hash_path(
            (
                (
                    +1,
                    data
                ),
                (
                    -1,
                    data
                )
            ),
            1
        ) == hashf(data, data)
    else:
        assert hash_path(
            (
                (
                    +1,
                    data
                ),
                (
                    -1,
                    data
                )
            ),
            0
        ) == hash_path(
            (
                (
                    +1,
                    data
                ),
                (
                    -1,
                    data
                )
            ),
            1
        ) == hashf(data, data)


@pytest.mark.parametrize('config', all_configs(option))
def test_3_elems_hash_path_case_1(config):
    engine = HashEngine(**config)

    hashf = engine.hash_pair
    hash_path = engine.hash_path
    data = record.encode(engine.encoding)

    if engine.security:
        assert hash_path(
            (
                (
                    +1,
                    data
                ),
                (
                    +1,
                    data
                ),
                (
                    'whatever',
                    data
                )
            ),
            0
        ) == hash_path(
            (
                (
                    +1,
                    data
                ),
                (
                    -1,
                    data
                ),
                (
                    'whatever',
                    data
                )
            ),
            1
        ) == hashf(
            hashf(
                data,
                data
            ),
            data
        )
    else:
        assert hash_path(
            (
                (
                    +1,
                    data
                ),
                (
                    +1,
                    data
                ),
                (
                    'whatever',
                    data
                )
            ),
            0

        ) == hash_path(
            (
                (
                    +1,
                    data
                ),
                (
                    -1,
                    data
                ),
                (
                    'whatever',
                    data
                )
            ),
            1
        ) == hashf(
            hashf(
                data,
                data),
            data
        )


@pytest.mark.parametrize('config', all_configs(option))
def test_3_elems_hash_path_case_2(config):
    engine = HashEngine(**config)

    hashf = engine.hash_pair
    hash_path = engine.hash_path
    data = record.encode(engine.encoding)

    if engine.security:
        assert hash_path(
            (
                (
                    'whatever',
                    data
                ),
                (
                    -1,
                    data
                ),
                (
                    -1,
                    data
                )
            ),
            2
        ) == hash_path(
            (
                (
                    'whatever',
                    data
                ),
                (
                    +1,
                    data
                ),
                (
                    -1,
                    data
                )
            ),
            1
        ) == hashf(
            data,
            hashf(
                data,
                data
            )
        )
    else:
        assert hash_path(
            (
                (
                    'whatever',
                    data
                ),
                (
                    -1,
                    data
                ),
                (
                    -1,
                    data
                )
            ),
            2
        ) == hash_path(
            (
                (
                    'whatever',
                    data
                ),
                (
                    +1,
                    data
                ),
                (
                    -1,
                    data
                )
            ),
            1
        ) == hashf(
            data,
            hashf(
                data,
                data
            )
        )


@pytest.mark.parametrize('config', all_configs(option))
def test_4_elems_hash_path_edge_case_1(config):
    engine = HashEngine(**config)

    hashf = engine.hash_pair
    hash_path = engine.hash_path
    data = record.encode(engine.encoding)

    if engine.security:
        assert hash_path(
            (
                (
                    +1,
                    data
                ),
                (
                    +1,
                    data
                ),
                (
                    +1,
                    data
                ),
                (
                    'whatever',
                    data
                )
            ),
            0
        ) == hashf(
            hashf(
                hashf(
                    data,
                    data
                ),
                data
            ),
            data
        )
    else:
        assert hash_path(
            (
                (
                    +1,
                    data
                ),
                (
                    +1,
                    data
                ),
                (
                    +1,
                    data
                ),
                (
                    'whatever',
                    data
                )
            ),
            0
        ) == hashf(
            hashf(
                hashf(
                    data,
                    data
                ),
                data
            ),
            data
        )


@pytest.mark.parametrize('config', all_configs(option))
def test_4_elems_hash_path_edge_case_2(config):
    engine = HashEngine(**config)

    hashf = engine.hash_pair
    hash_path = engine.hash_path
    data = record.encode(engine.encoding)

    if engine.security:
        assert hash_path(
            (
                (
                    'whatever',
                    data
                ),
                (
                    -1,
                    data
                ),
                (
                    -1,
                    data
                ),
                (
                    -1,
                    data
                )
            ),
            3
        ) == hashf(
            data,
            hashf(
                data,
                hashf(
                    data,
                    data
                )
            )
        )
    else:
        assert hash_path(
            (
                (
                    'whatever',
                    data
                ),
                (
                    -1,
                    data
                ),
                (
                    -1,
                    data
                ),
                (
                    -1,
                    data
                )
            ),
            3
        ) == hashf(
            data,
            hashf(
                data,
                hashf(
                    data,
                    data
                )
            )
        )


@pytest.mark.parametrize('config', all_configs(option))
def test_4_elems_hash_path(config):
    engine = HashEngine(**config)

    hashf = engine.hash_pair
    hash_path = engine.hash_path
    data = record.encode(engine.encoding)

    if engine.security:
        assert hash_path(
            (
                (
                    +1,
                    data
                ),
                (
                    +1,
                    data
                ),
                (
                    -1,
                    data
                ),
                (
                    -1,
                    data
                )
            ),
            1
        ) == hashf(
            hashf(
                data,
                hashf(
                    data,
                    data)
            ),
            data
        )
    else:
        assert hash_path(
            (
                (
                    +1,
                    data
                ),
                (
                    +1,
                    data
                ),
                (
                    -1,
                    data
                ),
                (
                    -1,
                    data
                )
            ),
            1
        ) == hashf(
            hashf(
                data,
                hashf(
                    data,
                    data
                )
            ),
            data
        )
