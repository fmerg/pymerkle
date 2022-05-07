"""
Tests hashing in no raw-bytes mode
"""

import pytest
import hashlib

from pymerkle.core.hashing import HashEngine, SUPPORTED_HASH_TYPES
from pymerkle.exceptions import EmptyPathException, UndecodableArgumentError
from tests.conftest import SUPPORTED_ENCODINGS


MESSAGE = 'oculusnonviditnecaurisaudivit'

engines = []
engines__hash_types__encodings__securities = []
engines__single_args = []

for security in (True, False):
    for hash_type in SUPPORTED_HASH_TYPES:
        for encoding in SUPPORTED_ENCODINGS:
            engine = HashEngine(
                hash_type=hash_type,
                encoding=encoding,
                raw_bytes=False,
                security=security
            )

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
                        MESSAGE
                    ),
                    (
                        engine,
                        bytes(MESSAGE, encoding)
                    )
                ]
            )


# .hash()

@pytest.mark.parametrize("engine, hash_type, encoding, security",
                         engines__hash_types__encodings__securities)
def test_single_string_hash(engine, hash_type, encoding, security):
    if security:
        assert engine.hash(MESSAGE) == bytes(
            getattr(hashlib, hash_type)(
                ('\x00%s' % MESSAGE).encode(encoding)).hexdigest(),
            encoding
        )
    else:
        assert engine.hash(MESSAGE) == bytes(
            getattr(hashlib, hash_type)(bytes(MESSAGE, encoding)).hexdigest(),
            encoding
        )


@pytest.mark.parametrize("engine, hash_type, encoding, security",
                         engines__hash_types__encodings__securities)
def test_single_bytes_hash(engine, hash_type, encoding, security):
    if security:
        assert engine.hash(bytes(MESSAGE, encoding)) == bytes(
            getattr(hashlib, hash_type)(
                bytes('\x00%s' % MESSAGE, encoding)).hexdigest(),
            encoding
        )
    else:
        assert engine.hash(bytes(MESSAGE, encoding)) == bytes(
            getattr(hashlib, hash_type)(bytes(MESSAGE, encoding)).hexdigest(),
            encoding
        )


@pytest.mark.parametrize("engine, hash_type, encoding, security",
                         engines__hash_types__encodings__securities)
def test_double_bytes_hash(engine, hash_type, encoding, security):
    if security:
        assert engine.hash(
            bytes(MESSAGE, encoding),
            bytes(MESSAGE, encoding)) == bytes(
            getattr(hashlib, hash_type)(
                bytes(
                    '\x01%s\x01%s' % (MESSAGE, MESSAGE),
                    encoding)
            ).hexdigest(),
            encoding
        )
    else:
        assert engine.hash(
            bytes(MESSAGE, encoding),
            bytes(MESSAGE, encoding)) == bytes(
                getattr(hashlib, hash_type)(
                    bytes(
                        MESSAGE + MESSAGE,
                        encoding
                    )).hexdigest(),
                encoding
        )


# multi_hash()

@pytest.mark.parametrize('engine', engines)
def test_0_elems_multi_hash(engine):
    with pytest.raises(EmptyPathException):
        assert engine.multi_hash((), start='anything')


@pytest.mark.parametrize('engine, single_arg', engines__single_args)
def test_1_elems_multi_hash(engine, single_arg):
    assert engine.multi_hash(
        ((+1, engine.hash(single_arg)),), start=0
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
                    bytes(MESSAGE, encoding)
                ),
                (
                    -1,
                    bytes(MESSAGE, encoding)
                )
            ),
            start=0
        ) == multi_hash(
            (
                (
                    +1,
                    bytes(MESSAGE, encoding)
                ),
                (
                    -1,
                    bytes(MESSAGE, encoding)
                )
            ),
            start=1
        ) == hash(bytes(MESSAGE, encoding), bytes(MESSAGE, encoding))
    else:
        assert multi_hash(
            (
                (
                    +1,
                    bytes(MESSAGE, encoding)
                ),
                (
                    -1,
                    bytes(MESSAGE, encoding)
                )
            ),
            start=0
        ) == multi_hash(
            (
                (
                    +1,
                    bytes(MESSAGE, encoding)
                ),
                (
                    -1,
                    bytes(MESSAGE, encoding)
                )
            ),
            start=1
        ) == hash('%s%s' % (MESSAGE, MESSAGE))


@pytest.mark.parametrize('engine', engines)
def test_3_elems_multi_hash_case_1(engine):
    hash = engine.hash
    multi_hash = engine.multi_hash
    encoding = engine.encoding
    if engine.security:
        assert multi_hash(
            signed_hashes=(
                (
                    +1,
                    bytes(MESSAGE, encoding)
                ),
                (
                    +1,
                    bytes(MESSAGE, encoding)
                ),
                (
                    '_anything_',
                    bytes(MESSAGE, encoding)
                )
            ),
            start=0
        ) == multi_hash(
            signed_hashes=(
                (
                    +1,
                    bytes(MESSAGE, encoding)
                ),
                (
                    -1,
                    bytes(MESSAGE, encoding)
                ),
                (
                    '_anything_',
                    bytes(MESSAGE, encoding)
                )
            ),
            start=1
        ) == hash(
            hash(
                bytes(MESSAGE, encoding),
                bytes(MESSAGE, encoding)
            ),
            bytes(MESSAGE, encoding)
        )
    else:
        assert multi_hash(
            signed_hashes=(
                (
                    +1,
                    bytes(MESSAGE, encoding)
                ),
                (
                    +1,
                    bytes(MESSAGE, encoding)
                ),
                (
                    '_anything_',
                    bytes(MESSAGE, encoding)
                )
            ),
            start=0
        ) == multi_hash(
            signed_hashes=(
                (
                    +1,
                    bytes(MESSAGE, encoding)
                ),
                (
                    -1,
                    bytes(MESSAGE, encoding)
                ),
                (
                    '_anything_',
                    bytes(MESSAGE, encoding)
                )
            ),
            start=1
        ) == hash(
            hash('%s%s' % (MESSAGE, MESSAGE)),
            bytes(MESSAGE, encoding)
        )


@pytest.mark.parametrize('engine', engines)
def test_3_elems_multi_hash_case_2(engine):
    hash = engine.hash
    multi_hash = engine.multi_hash
    encoding = engine.encoding
    if engine.security:
        assert multi_hash(
            signed_hashes=(
                (
                    '_anything_',
                    bytes(MESSAGE, encoding)
                ),
                (
                    -1,
                    bytes(MESSAGE, encoding)
                ),
                (
                    -1,
                    bytes(MESSAGE, encoding)
                )
            ),
            start=2
        ) == multi_hash(
            signed_hashes=(
                (
                    '_anything_',
                    bytes(MESSAGE, encoding)
                ),
                (
                    +1,
                    bytes(MESSAGE, encoding)
                ),
                (
                    -1,
                    bytes(MESSAGE, encoding)
                )
            ),
            start=1
        ) == hash(
            bytes(MESSAGE, encoding),
            hash(
                bytes(MESSAGE, encoding),
                bytes(MESSAGE, encoding)
            )
        )
    else:
        assert multi_hash(
            signed_hashes=(
                (
                    '_anything_',
                    bytes(MESSAGE, encoding)
                ),
                (
                    -1,
                    bytes(MESSAGE, encoding)
                ),
                (
                    -1,
                    bytes(MESSAGE, encoding)
                )
            ),
            start=2
        ) == multi_hash(
            signed_hashes=(
                (
                    '_anything_',
                    bytes(MESSAGE, encoding)
                ),
                (
                    +1,
                    bytes(MESSAGE, encoding)
                ),
                (
                    -1,
                    bytes(MESSAGE, encoding)
                )
            ),
            start=1
        ) == hash(
            bytes(MESSAGE, encoding),
            hash('%s%s' % (MESSAGE, MESSAGE))
        )


@pytest.mark.parametrize('engine', engines)
def test_4_elems_multi_hash_edge_case_1(engine):
    hash = engine.hash
    multi_hash = engine.multi_hash
    encoding = engine.encoding
    if engine.security:
        assert multi_hash(
            signed_hashes=(
                (
                    +1,
                    bytes(MESSAGE, encoding)
                ),
                (
                    +1,
                    bytes(MESSAGE, encoding)
                ),
                (
                    +1,
                    bytes(MESSAGE, encoding)
                ),
                (
                    '_anything_',
                    bytes(MESSAGE, encoding)
                )
            ),
            start=0
        ) == hash(
            hash(
                hash(
                    bytes(MESSAGE, encoding),
                    bytes(MESSAGE, encoding)
                ),
                bytes(MESSAGE, encoding)
            ),
            bytes(MESSAGE, encoding)
        )
    else:
        assert multi_hash(
            signed_hashes=(
                (
                    +1,
                    bytes(MESSAGE, encoding)
                ),
                (
                    +1,
                    bytes(MESSAGE, encoding)
                ),
                (
                    +1,
                    bytes(MESSAGE, encoding)
                ),
                (
                    '_anything_',
                    bytes(MESSAGE, encoding)
                )
            ),
            start=0
        ) == hash(
            hash(
                hash('%s%s' % (MESSAGE, MESSAGE)),
                bytes(MESSAGE, encoding)
            ),
            bytes(MESSAGE, encoding)
        )


@pytest.mark.parametrize('engine', engines)
def test_4_elems_multi_hash_edge_case_2(engine):
    hash = engine.hash
    multi_hash = engine.multi_hash
    encoding = engine.encoding
    if engine.security:
        assert multi_hash(
            signed_hashes=(
                (
                    '_anything_',
                    bytes(MESSAGE, encoding)
                ),
                (
                    -1,
                    bytes(MESSAGE, encoding)
                ),
                (
                    -1,
                    bytes(MESSAGE, encoding)
                ),
                (
                    -1,
                    bytes(MESSAGE, encoding)
                )
            ),
            start=3
        ) == hash(
            bytes(MESSAGE, encoding),
            hash(
                bytes(MESSAGE, encoding),
                hash(
                    bytes(MESSAGE, encoding),
                    bytes(MESSAGE, encoding)
                )
            )
        )
    else:
        assert multi_hash(
            signed_hashes=(
                (
                    '_anything_',
                    bytes(MESSAGE, encoding)
                ),
                (
                    -1,
                    bytes(MESSAGE, encoding)
                ),
                (
                    -1,
                    bytes(MESSAGE, encoding)
                ),
                (
                    -1,
                    bytes(MESSAGE, encoding)
                )
            ),
            start=3
        ) == hash(
            bytes(MESSAGE, encoding),
            hash(
                bytes(MESSAGE, encoding),
                hash('%s%s' % (MESSAGE, MESSAGE))
            )
        )


@pytest.mark.parametrize('engine', engines)
def test_4_elems_multi_hash(engine):
    hash = engine.hash
    multi_hash = engine.multi_hash
    encoding = engine.encoding
    if engine.security:
        assert multi_hash(
            signed_hashes=(
                (
                    +1,
                    bytes(MESSAGE, encoding)
                ),
                (
                    +1,
                    bytes(MESSAGE, encoding)
                ),
                (
                    -1,
                    bytes(MESSAGE, encoding)
                ),
                (
                    -1,
                    bytes(MESSAGE, encoding)
                )
            ),
            start=1
        ) == hash(
            hash(
                bytes(MESSAGE, encoding),
                hash(
                    bytes(MESSAGE, encoding),
                    bytes(MESSAGE, encoding))
            ),
            bytes(MESSAGE, encoding)
        )
    else:
        assert multi_hash(
            signed_hashes=(
                (
                    +1,
                    bytes(MESSAGE, encoding)
                ),
                (
                    +1,
                    bytes(MESSAGE, encoding)
                ),
                (
                    -1,
                    bytes(MESSAGE, encoding)
                ),
                (
                    -1,
                    bytes(MESSAGE, encoding)
                )
            ),
            start=1
        ) == hash(
            hash(
                bytes(MESSAGE, encoding),
                hash('%s%s' % (MESSAGE, MESSAGE))
            ),
            bytes(MESSAGE, encoding)
        )
