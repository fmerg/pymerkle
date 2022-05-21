"""
"""

import pytest
import hashlib

from pymerkle.hashing import HashEngine, SUPPORTED_HASH_TYPES, \
    EmptyPathException, UnsupportedParameter

from tests.conftest import option, resolve_encodings

message = 'oculusnonviditnecaurisaudivit'

engines = []
engines__hash_types__encodings__securities = []
engines__single_args = []

for security in (True, False):
    for hash_type in SUPPORTED_HASH_TYPES:
        for encoding in resolve_encodings(option):
            config = {'hash_type': hash_type, 'encoding': encoding,
                      'security': security}
            engine = HashEngine(**config)

            engines.append(engine)
            engines__hash_types__encodings__securities.extend(
                [
                    (
                        engine,
                        hash_type,
                        encoding,
                        security
                    )
                ]
            )

            engines__single_args.extend(
                [
                    (
                        engine,
                        message
                    ),
                    (
                        engine,
                        bytes(message, encoding)
                    )
                ]
            )


# hash

@pytest.mark.parametrize("engine, hash_type, encoding, security",
                         engines__hash_types__encodings__securities)
def test_single_string_hash(engine, hash_type, encoding, security):
    if security:
        assert engine.hash(message) == bytes(
            getattr(hashlib, hash_type)(
                ('\x00').encode(encoding) +
                (message).encode(encoding)
            ).hexdigest(),
            encoding
        )
    else:
        assert engine.hash(message) == bytes(
            getattr(hashlib, hash_type)(bytes(message, encoding)).hexdigest(),
            encoding
        )


@pytest.mark.parametrize("engine, hash_type, encoding, security",
                         engines__hash_types__encodings__securities)
def test_single_bytes_hash(engine, hash_type, encoding, security):
    if security:
        assert engine.hash(bytes(message, encoding)) == bytes(
            getattr(hashlib, hash_type)(
                bytes('\x00', encoding) +
                bytes(message, encoding)
            ).hexdigest(),
            encoding
        )
    else:
        assert engine.hash(bytes(message, encoding)) == bytes(
            getattr(hashlib, hash_type)(bytes(message, encoding)).hexdigest(),
            encoding
        )


@pytest.mark.parametrize("engine, hash_type, encoding, security",
                         engines__hash_types__encodings__securities)
def test_double_bytes_hash(engine, hash_type, encoding, security):
    if security:
        assert engine.hash(
            bytes(message, encoding),
            bytes(message, encoding)) == bytes(
            getattr(hashlib, hash_type)(
                bytes('\x01', encoding) +
                bytes(message, encoding) +
                bytes('\x01', encoding) +
                bytes(message, encoding)
            ).hexdigest(),
            encoding
        )
    else:
        assert engine.hash(
            bytes(message, encoding),
            bytes(message, encoding)) == bytes(
                getattr(hashlib, hash_type)(
                    bytes(message, encoding) +
                    bytes(message, encoding)
                ).hexdigest(),
                encoding
        )


# multi_hash

@pytest.mark.parametrize('engine', engines)
def test_0_elems_multi_hash(engine):
    with pytest.raises(EmptyPathException):
        assert engine.multi_hash((), 'anything')


@pytest.mark.parametrize('engine, single_arg', engines__single_args)
def test_1_elems_multi_hash(engine, single_arg):
    assert engine.multi_hash(
        ((+1, engine.hash(single_arg)),), 0
    ) == engine.hash(single_arg)


@pytest.mark.parametrize('engine', engines)
def test_2_elems_multi_hash(engine):
    hash = engine.hash
    multi_hash = engine.multi_hash
    encoding = engine.encoding
    if engine.security:
        assert multi_hash(
            (
                (
                    +1,
                    bytes(message, encoding)
                ),
                (
                    -1,
                    bytes(message, encoding)
                )
            ),
            0
        ) == multi_hash(
            (
                (
                    +1,
                    bytes(message, encoding)
                ),
                (
                    -1,
                    bytes(message, encoding)
                )
            ),
            1
        ) == hash(bytes(message, encoding), bytes(message, encoding))
    else:
        assert multi_hash(
            (
                (
                    +1,
                    bytes(message, encoding)
                ),
                (
                    -1,
                    bytes(message, encoding)
                )
            ),
            0
        ) == multi_hash(
            (
                (
                    +1,
                    bytes(message, encoding)
                ),
                (
                    -1,
                    bytes(message, encoding)
                )
            ),
            1
        ) == hash(bytes(message, encoding), bytes(message, encoding))


@pytest.mark.parametrize('engine', engines)
def test_3_elems_multi_hash_case_1(engine):
    hash = engine.hash
    multi_hash = engine.multi_hash
    encoding = engine.encoding
    if engine.security:
        assert multi_hash(
            (
                (
                    +1,
                    bytes(message, encoding)
                ),
                (
                    +1,
                    bytes(message, encoding)
                ),
                (
                    'whatever',
                    bytes(message, encoding)
                )
            ),
            0
        ) == multi_hash(
            (
                (
                    +1,
                    bytes(message, encoding)
                ),
                (
                    -1,
                    bytes(message, encoding)
                ),
                (
                    'whatever',
                    bytes(message, encoding)
                )
            ),
            1
        ) == hash(
            hash(
                bytes(message, encoding),
                bytes(message, encoding)
            ),
            bytes(message, encoding)
        )
    else:
        assert multi_hash(
            (
                (
                    +1,
                    bytes(message, encoding)
                ),
                (
                    +1,
                    bytes(message, encoding)
                ),
                (
                    'whatever',
                    bytes(message, encoding)
                )
            ),
            0

        ) == multi_hash(
            (
                (
                    +1,
                    bytes(message, encoding)
                ),
                (
                    -1,
                    bytes(message, encoding)
                ),
                (
                    'whatever',
                    bytes(message, encoding)
                )
            ),
            1
        ) == hash(
            hash(
                bytes(message, encoding),
                bytes(message, encoding)),
            bytes(message, encoding)
        )


@pytest.mark.parametrize('engine', engines)
def test_3_elems_multi_hash_case_2(engine):
    hash = engine.hash
    multi_hash = engine.multi_hash
    encoding = engine.encoding
    if engine.security:
        assert multi_hash(
            (
                (
                    'whatever',
                    bytes(message, encoding)
                ),
                (
                    -1,
                    bytes(message, encoding)
                ),
                (
                    -1,
                    bytes(message, encoding)
                )
            ),
            2
        ) == multi_hash(
            (
                (
                    'whatever',
                    bytes(message, encoding)
                ),
                (
                    +1,
                    bytes(message, encoding)
                ),
                (
                    -1,
                    bytes(message, encoding)
                )
            ),
            1
        ) == hash(
            bytes(message, encoding),
            hash(
                bytes(message, encoding),
                bytes(message, encoding)
            )
        )
    else:
        assert multi_hash(
            (
                (
                    'whatever',
                    bytes(message, encoding)
                ),
                (
                    -1,
                    bytes(message, encoding)
                ),
                (
                    -1,
                    bytes(message, encoding)
                )
            ),
            2
        ) == multi_hash(
            (
                (
                    'whatever',
                    bytes(message, encoding)
                ),
                (
                    +1,
                    bytes(message, encoding)
                ),
                (
                    -1,
                    bytes(message, encoding)
                )
            ),
            1
        ) == hash(
            bytes(message, encoding),
            hash(
                bytes(message, encoding),
                bytes(message, encoding)
            )
        )


@pytest.mark.parametrize('engine', engines)
def test_4_elems_multi_hash_edge_case_1(engine):
    hash = engine.hash
    multi_hash = engine.multi_hash
    encoding = engine.encoding
    if engine.security:
        assert multi_hash(
            (
                (
                    +1,
                    bytes(message, encoding)
                ),
                (
                    +1,
                    bytes(message, encoding)
                ),
                (
                    +1,
                    bytes(message, encoding)
                ),
                (
                    'whatever',
                    bytes(message, encoding)
                )
            ),
            0
        ) == hash(
            hash(
                hash(
                    bytes(message, encoding),
                    bytes(message, encoding)
                ),
                bytes(message, encoding)
            ),
            bytes(message, encoding)
        )
    else:
        assert multi_hash(
            (
                (
                    +1,
                    bytes(message, encoding)
                ),
                (
                    +1,
                    bytes(message, encoding)
                ),
                (
                    +1,
                    bytes(message, encoding)
                ),
                (
                    'whatever',
                    bytes(message, encoding)
                )
            ),
            0
        ) == hash(
            hash(
                hash(
                    bytes(message, encoding),
                    bytes(message, encoding)
                ),
                bytes(message, encoding)
            ),
            bytes(message, encoding)
        )


@pytest.mark.parametrize('engine', engines)
def test_4_elems_multi_hash_edge_case_2(engine):
    hash = engine.hash
    multi_hash = engine.multi_hash
    encoding = engine.encoding
    if engine.security:
        assert multi_hash(
            (
                (
                    'whatever',
                    bytes(message, encoding)
                ),
                (
                    -1,
                    bytes(message, encoding)
                ),
                (
                    -1,
                    bytes(message, encoding)
                ),
                (
                    -1,
                    bytes(message, encoding)
                )
            ),
            3
        ) == hash(
            bytes(message, encoding),
            hash(
                bytes(message, encoding),
                hash(
                    bytes(message, encoding),
                    bytes(message, encoding)
                )
            )
        )
    else:
        assert multi_hash(
            (
                (
                    'whatever',
                    bytes(message, encoding)
                ),
                (
                    -1,
                    bytes(message, encoding)
                ),
                (
                    -1,
                    bytes(message, encoding)
                ),
                (
                    -1,
                    bytes(message, encoding)
                )
            ),
            3
        ) == hash(
            bytes(message, encoding),
            hash(
                bytes(message, encoding),
                hash(
                    bytes(message, encoding),
                    bytes(message, encoding)
                )
            )
        )


@pytest.mark.parametrize('engine', engines)
def test_4_elems_multi_hash(engine):
    hash = engine.hash
    multi_hash = engine.multi_hash
    encoding = engine.encoding
    if engine.security:
        assert multi_hash(
            (
                (
                    +1,
                    bytes(message, encoding)
                ),
                (
                    +1,
                    bytes(message, encoding)
                ),
                (
                    -1,
                    bytes(message, encoding)
                ),
                (
                    -1,
                    bytes(message, encoding)
                )
            ),
            1
        ) == hash(
            hash(
                bytes(message, encoding),
                hash(
                    bytes(message, encoding),
                    bytes(message, encoding))
            ),
            bytes(message, encoding)
        )
    else:
        assert multi_hash(
            (
                (
                    +1,
                    bytes(message, encoding)
                ),
                (
                    +1,
                    bytes(message, encoding)
                ),
                (
                    -1,
                    bytes(message, encoding)
                ),
                (
                    -1,
                    bytes(message, encoding)
                )
            ),
            1
        ) == hash(
            hash(
                bytes(message, encoding),
                hash(
                    bytes(message, encoding),
                    bytes(message, encoding)
                )
            ),
            bytes(message, encoding)
        )
