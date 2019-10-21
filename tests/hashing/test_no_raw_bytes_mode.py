"""
Tests hashing in no raw-bytes mode
"""

import pytest
import hashlib

from pymerkle.hashing import HashMachine, HASH_TYPES
from pymerkle.exceptions import EmptyPathException, UndecodableArgumentError
from tests.config import ENCODINGS


MESSAGE = 'oculusnonviditnecaurisaudivit'

__machines = []
__machines__hash_types__encodings__securities = []
__machines__single_args = []

for security in (True, False):
    for hash_type in HASH_TYPES:
        for encoding in ENCODINGS:
            machine = HashMachine(
                hash_type=hash_type,
                encoding=encoding,
                raw_bytes=False,
                security=security
            )

            __machines.append(machine)
            __machines__hash_types__encodings__securities.extend(
                [
                    (
                        machine,
                        hash_type,
                        encoding,
                        security
                    )
                ]
            )
            __machines__single_args.extend(
                [
                    (
                        machine,
                        MESSAGE
                    ),
                    (
                        machine,
                        bytes(MESSAGE, encoding)
                    )
                ]
            )


# .hash()

@pytest.mark.parametrize("machine, hash_type, encoding, security",
    __machines__hash_types__encodings__securities)
def test_single_string_hash(machine, hash_type, encoding, security):
    if security:
        assert machine.hash(MESSAGE) == bytes(
            getattr(hashlib, hash_type)(
            ('\x00%s' % MESSAGE).encode(encoding)).hexdigest(),
            encoding
        )
    else:
        assert machine.hash(MESSAGE) == bytes(
            getattr(hashlib, hash_type)(bytes(MESSAGE, encoding)).hexdigest(),
            encoding
        )


@pytest.mark.parametrize("machine, hash_type, encoding, security",
    __machines__hash_types__encodings__securities)
def test_single_bytes_hash(machine, hash_type, encoding, security):
    if security:
        assert machine.hash(bytes(MESSAGE, encoding)) == bytes(
            getattr(hashlib, hash_type)(
            bytes('\x00%s' % MESSAGE, encoding)).hexdigest(),
            encoding
        )
    else:
        assert machine.hash(bytes(MESSAGE, encoding)) == bytes(
            getattr(hashlib, hash_type)(bytes(MESSAGE, encoding)).hexdigest(),
            encoding
        )


@pytest.mark.parametrize("machine, hash_type, encoding, security",
    __machines__hash_types__encodings__securities)
def test_double_bytes_hash(machine, hash_type, encoding, security):
    if security:
        assert machine.hash(
            bytes(MESSAGE, encoding),
            bytes(MESSAGE, encoding)) == bytes(
            getattr(hashlib,hash_type)(
                bytes(
                    '\x01%s\x01%s' % (MESSAGE, MESSAGE),
                    encoding)
            ).hexdigest(),
            encoding
        )
    else:
        assert machine.hash(
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

@pytest.mark.parametrize('machine', __machines)
def test_0_elems_multi_hash(machine):
    with pytest.raises(EmptyPathException):
        assert machine.multi_hash((), start='anything')

@pytest.mark.parametrize('machine, single_arg', __machines__single_args)
def test_1_elems_multi_hash(machine, single_arg):
    assert machine.multi_hash(
        ((+1, machine.hash(single_arg)),), start=0
    ) == machine.hash(single_arg)

@pytest.mark.parametrize('machine', __machines)
def test_2_elems_multi_hash(machine):
    hash = machine.hash
    multi_hash = machine.multi_hash
    encoding = machine.encoding
    if machine.security:
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


@pytest.mark.parametrize('machine', __machines)
def test_3_elems_multi_hash_case_1(machine):
    hash = machine.hash
    multi_hash = machine.multi_hash
    encoding = machine.encoding
    if machine.security:
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


@pytest.mark.parametrize('machine', __machines)
def test_3_elems_multi_hash_case_2(machine):
    hash = machine.hash
    multi_hash = machine.multi_hash
    encoding = machine.encoding
    if machine.security:
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


@pytest.mark.parametrize('machine', __machines)
def test_4_elems_multi_hash_edge_case_1(machine):
    hash = machine.hash
    multi_hash = machine.multi_hash
    encoding = machine.encoding
    if machine.security:
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


@pytest.mark.parametrize('machine', __machines)
def test_4_elems_multi_hash_edge_case_2(machine):
    hash = machine.hash
    multi_hash = machine.multi_hash
    encoding = machine.encoding
    if machine.security:
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


@pytest.mark.parametrize('machine', __machines)
def test_4_elems_multi_hash(machine):
    hash = machine.hash
    multi_hash = machine.multi_hash
    encoding = machine.encoding
    if machine.security:
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
