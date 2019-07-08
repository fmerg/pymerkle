"""Tests the hashing module
"""

import pytest
from pymerkle import hashing
from pymerkle.exceptions import EmptyPathException, UndecodableArgumentError

import hashlib

HASH_TYPES = hashing.HASH_TYPES
ENCODINGS  = hashing.ENCODINGS

MESSAGE = 'oculusnonviditnecaurisaudivit'

_machines                                    = []
_machines__hash_types__encodings__securities = []
_machines__single_args                       = []

for _security in (True, False):
    for _hash_type in HASH_TYPES:
        for _encoding in ENCODINGS:

            _machine = hashing.hash_machine(
                hash_type=_hash_type,
                encoding=_encoding,
                security=_security
            )

            _machines.append(_machine)

            _machines__hash_types__encodings__securities.extend(
                [
                    (
                        _machine,
                        _hash_type,
                        _encoding,
                        _security
                    )
                ]
            )

            _machines__single_args.extend(
                [
                    (
                        _machine,
                        MESSAGE
                    ),
                    (
                        _machine,
                        bytes(MESSAGE, _encoding)
                    ),
                    (
                        _machine,
                        bytearray(MESSAGE, _encoding)
                    )
                ]
            )


# ------------------------------ .hash() testing ------------------------------


@pytest.mark.parametrize("_machine, _hash_type, _encoding, _security", _machines__hash_types__encodings__securities)
def test_single_string_hash(_machine, _hash_type, _encoding, _security):
    """Tests single string hashing
    """

    if _security:
        assert _machine.hash(MESSAGE) == bytes(
            getattr(hashlib, _hash_type)(('\x00%s' % MESSAGE).encode(_encoding)).hexdigest(),
            _encoding
        )
    else:
        assert _machine.hash(MESSAGE) == bytes(
            getattr(hashlib, _hash_type)(bytes(MESSAGE, _encoding)).hexdigest(),
            _encoding
        )


@pytest.mark.parametrize("_machine, _hash_type, _encoding, _security", _machines__hash_types__encodings__securities)
def test_single_bytes_hash(_machine, _hash_type, _encoding, _security):
    """Tests single bytes object hashing
    """

    if _security:
        assert _machine.hash(bytes(MESSAGE, _encoding)) == bytes(
            getattr(hashlib, _hash_type)(bytes('\x00%s' % MESSAGE, _encoding)).hexdigest(),
            _encoding
        )
    else:
        assert _machine.hash(bytes(MESSAGE, _encoding)) == bytes(
            getattr(hashlib, _hash_type)(bytes(MESSAGE, _encoding)).hexdigest(),
            _encoding
        )


@pytest.mark.parametrize("_machine, _hash_type, _encoding, _security", _machines__hash_types__encodings__securities)
def test_single_bytearray_hash(_machine, _hash_type, _encoding, _security):
    """Tests single bytearray object hashing
    """

    if _security:
        assert _machine.hash(bytearray(MESSAGE, _encoding)) == bytearray(
            getattr(hashlib, _hash_type)(bytearray('\x00%s' % MESSAGE, _encoding)).hexdigest(),
            _encoding
        )
    else:
        assert _machine.hash(bytearray(MESSAGE, _encoding)) == bytearray(
            getattr(hashlib, _hash_type)(bytearray(MESSAGE, _encoding)).hexdigest(),
            _encoding
        )


@pytest.mark.parametrize("_machine, _hash_type, _encoding, _security", _machines__hash_types__encodings__securities)
def test_double_bytes_hash(_machine, _hash_type, _encoding, _security):
    """Tests double-argument hashing for given bytes objects
    """

    if _security:

        assert _machine.hash(
            bytes(MESSAGE, _encoding),
            bytes(MESSAGE, _encoding)) == bytes(
            getattr(hashlib,_hash_type)(
                bytes(
                    '\x01%s\x01%s' % (MESSAGE, MESSAGE),
                    _encoding)
            ).hexdigest(),
            _encoding
        )
    else:
        assert _machine.hash(
            bytes(MESSAGE, _encoding),
            bytes(MESSAGE, _encoding)) == bytes(
                getattr(hashlib, _hash_type)(
                    bytes(
                        MESSAGE + MESSAGE,
                        _encoding
                    )).hexdigest(),
                _encoding
            )


@pytest.mark.parametrize("_machine, _hash_type, _encoding, _security", _machines__hash_types__encodings__securities)
def test_double_bytearray_hash(_machine, _hash_type, _encoding, _security):
    """Tests double-argument hashing for given bytearray objects
    """

    if _security:

        assert _machine.hash(
            bytearray(MESSAGE, _encoding),
            bytearray(MESSAGE, _encoding)) == bytearray(
            getattr(hashlib,_hash_type)(
                bytearray(
                    '\x01%s\x01%s' % (MESSAGE, MESSAGE),
                    _encoding)
            ).hexdigest(),
            _encoding
        )
    else:
        assert _machine.hash(
            bytearray(MESSAGE, _encoding),
            bytearray(MESSAGE, _encoding)) == bytearray(
                getattr(hashlib, _hash_type)(
                    bytearray(
                        MESSAGE + MESSAGE,
                        _encoding
                    )).hexdigest(),
                _encoding
            )


# Exceptions testing

_undecodableArgumentErrors = [

    (b'\xc2', 'ascii', True),
    (b'\xc2', 'ascii', False),
    (b'\x72', 'cp424', True),
    (b'\x72', 'cp424', False),
    (b'\xc2', 'hz', True),
    (b'\xc2', 'hz', False),
    (b'\xc2', 'utf_7', True),
    (b'\xc2', 'utf_7', False),
    (b'\x74', 'utf_16', True),
    (b'\x74', 'utf_16', False),
    (b'\x74', 'utf_16_le', True),
    (b'\x74', 'utf_16_le', False),
    (b'\x74', 'utf_16_be', True),
    (b'\x74', 'utf_16_be', False),
    (b'\x74', 'utf_32', True),
    (b'\x74', 'utf_32', False),
    (b'\x74', 'utf_32_le', True),
    (b'\x74', 'utf_32_le', False),
    (b'\x74', 'utf_32_be', True),
    (b'\x74', 'utf_32_be', False),
    (b'\xc2', 'iso2022_jp', True),
    (b'\xc2', 'iso2022_jp', False),
    (b'\xc2', 'iso2022_jp_1', True),
    (b'\xc2', 'iso2022_jp_1', False),
    (b'\xc2', 'iso2022_jp_2', True),
    (b'\xc2', 'iso2022_jp_2', False),
    (b'\xc2', 'iso2022_jp_3', True),
    (b'\xc2', 'iso2022_jp_3', False),
    (b'\xc2', 'iso2022_jp_ext', True),
    (b'\xc2', 'iso2022_jp_ext', False),
    (b'\xc2', 'iso2022_jp_2004', True),
    (b'\xc2', 'iso2022_jp_2004', False),
    (b'\xc2', 'iso2022_kr', True),
    (b'\xc2', 'iso2022_kr', False),
    (b'\xae', 'iso8859_3', True),
    (b'\xae', 'iso8859_3', False),
    (b'\xb6', 'iso8859_6', True),
    (b'\xb6', 'iso8859_6', False),
    (b'\xae', 'iso8859_7', True),
    (b'\xae', 'iso8859_7', False),
    (b'\xc2', 'iso8859_8', True),
    (b'\xc2', 'iso8859_8', False),
]

@pytest.mark.parametrize('_byte, _encoding, _security', _undecodableArgumentErrors)
def test_single_undecodableArgumentError(_byte, _encoding, _security):

    _machine = hashing.hash_machine(encoding=_encoding, security=_security)

    with pytest.raises(UndecodableArgumentError):
        _machine.hash(_byte)

@pytest.mark.parametrize('_byte, _encoding, _security', _undecodableArgumentErrors)
def test_double_undecodableArgumentError(_byte, _encoding, _security):

    _machine = hashing.hash_machine(encoding=_encoding, security=_security)

    with pytest.raises(UndecodableArgumentError):
        _machine.hash(_byte, _byte)



# --------------------------- .multi_hash() testing ---------------------------


@pytest.mark.parametrize('_machine', _machines)
def test_0_elems_multi_hash(_machine):
    """Tests that the EmptyPathException is raised then the .multi_hash() method is called with an empty sequence
    """

    with pytest.raises(EmptyPathException):
        assert _machine.multi_hash((), start='anything')


@pytest.mark.parametrize('_machine, _single_arg', _machines__single_args)
def test_1_elems_multi_hash(_machine, _single_arg):

    assert _machine.multi_hash(
        ((+1, _machine.hash(_single_arg)),), start=0
    ) == _machine.hash(_single_arg)


@pytest.mark.parametrize('_machine', _machines)
def test_2_elems_multi_hash(_machine):

    _hash       = _machine.hash
    _multi_hash = _machine.multi_hash
    _encoding   = _machine.ENCODING

    if _machine.SECURITY:

        assert _multi_hash(

                (
                    (
                        +1,
                         bytes(MESSAGE, _encoding)
                    ),
                    (
                        -1,
                         bytes(MESSAGE, _encoding)
                    )
                ),
                start=0

        ) == _multi_hash(

                (
                    (
                        +1,
                        bytes(MESSAGE, _encoding)
                    ),
                    (
                        -1,
                        bytes(MESSAGE, _encoding)
                    )
                ),
                start=1

        ) == _hash(bytes(MESSAGE, _encoding), bytes(MESSAGE, _encoding))
    else:
        assert _multi_hash(

                (
                    (
                        +1,
                        bytes(MESSAGE, _encoding)
                    ),
                    (
                        -1,
                        bytes(MESSAGE,_encoding)
                    )
                ),
                start=0

        ) == _multi_hash(

                (
                    (
                        +1,
                        bytes(MESSAGE, _encoding)
                    ),
                    (
                        -1,
                        bytes(MESSAGE, _encoding)
                    )
                ),
                start=1

        ) == _hash('%s%s' % (MESSAGE, MESSAGE))


@pytest.mark.parametrize('_machine', _machines)
def test_3_elems_multi_hash_case_1(_machine):

    _hash       = _machine.hash
    _multi_hash = _machine.multi_hash
    _encoding   = _machine.ENCODING

    if _machine.SECURITY:

        assert _multi_hash(

                    signed_hashes=(
                        (
                            +1,
                            bytes(MESSAGE, _encoding)
                        ),
                        (
                            +1,
                            bytes(MESSAGE, _encoding)
                        ),
                        (
                            '_anything_',
                            bytes(MESSAGE, _encoding)
                        )
                    ),
                    start=0

            ) == _multi_hash(

                    signed_hashes=(
                        (
                            +1,
                            bytes(MESSAGE, _encoding)
                        ),
                        (
                            -1,
                            bytes(MESSAGE, _encoding)
                        ),
                        (
                            '_anything_',
                            bytes(MESSAGE, _encoding)
                        )
                    ),
                    start=1

            ) == _hash(
                    _hash(
                        bytes(MESSAGE, _encoding),
                        bytes(MESSAGE, _encoding)
                    ),
                    bytes(MESSAGE, _encoding)
                )
    else:
        assert _multi_hash(

                    signed_hashes=(
                        (
                            +1,
                            bytes(MESSAGE, _encoding)
                        ),
                        (
                            +1,
                            bytes(MESSAGE, _encoding)
                        ),
                        (
                            '_anything_',
                            bytes(MESSAGE, _encoding)
                        )
                    ),
                    start=0

            ) == _multi_hash(

                    signed_hashes=(
                        (
                            +1,
                            bytes(MESSAGE, _encoding)
                        ),
                        (
                            -1,
                            bytes(MESSAGE, _encoding)
                        ),
                        (
                            '_anything_',
                            bytes(MESSAGE, _encoding)
                        )
                    ),
                    start=1

            ) == _hash(
                    _hash('%s%s' % (MESSAGE, MESSAGE)),
                    bytes(MESSAGE, _encoding)
                )


@pytest.mark.parametrize('_machine', _machines)
def test_3_elems_multi_hash_case_2(_machine):

    _hash       = _machine.hash
    _multi_hash = _machine.multi_hash
    _encoding   = _machine.ENCODING

    if _machine.SECURITY:

        assert _multi_hash(

                signed_hashes=(
                    (
                        '_anything_',
                         bytes(MESSAGE, _encoding)
                    ),
                    (
                        -1,
                        bytes(MESSAGE, _encoding)
                    ),
                    (
                        -1,
                        bytes(MESSAGE, _encoding)
                    )
                ),
                start=2

        ) == _multi_hash(

                signed_hashes=(
                    (
                        '_anything_',
                         bytes(MESSAGE, _encoding)
                    ),
                    (
                        +1,
                        bytes(MESSAGE, _encoding)
                    ),
                    (
                        -1,
                        bytes(MESSAGE, _encoding)
                    )
                ),
                start=1

        ) == _hash(
                bytes(MESSAGE, _encoding),
                _hash(
                    bytes(MESSAGE, _encoding),
                    bytes(MESSAGE, _encoding)
                )
            )
    else:
        assert _multi_hash(

                signed_hashes=(
                    (
                        '_anything_',
                         bytes(MESSAGE, _encoding)
                    ),
                    (
                        -1,
                        bytes(MESSAGE, _encoding)
                    ),
                    (
                        -1,
                        bytes(MESSAGE, _encoding)
                    )
                ),
                start=2

        ) == _multi_hash(

                signed_hashes=(
                    (
                        '_anything_',
                         bytes(MESSAGE, _encoding)
                    ),
                    (
                        +1,
                        bytes(MESSAGE, _encoding)
                    ),
                    (
                        -1,
                        bytes(MESSAGE, _encoding)
                    )
                ),
                start=1

        ) == _hash(
                bytes(MESSAGE, _encoding),
                _hash('%s%s' % (MESSAGE, MESSAGE))
            )


@pytest.mark.parametrize('_machine', _machines)
def test_4_elems_multi_hash_edge_case_1(_machine):

    _hash       = _machine.hash
    _multi_hash = _machine.multi_hash
    _encoding   = _machine.ENCODING

    if _machine.SECURITY:

        assert _multi_hash(

                signed_hashes=(
                    (
                        +1,
                        bytes(MESSAGE, _encoding)
                    ),
                    (
                        +1,
                        bytes(MESSAGE, _encoding)
                    ),
                    (
                        +1,
                        bytes(MESSAGE, _encoding)
                    ),
                    (
                        '_anything_',
                        bytes(MESSAGE, _encoding)
                    )
                ),
                start=0

        ) == _hash(
                _hash(
                    _hash(
                        bytes(MESSAGE, _encoding),
                        bytes(MESSAGE, _encoding)
                    ),
                    bytes(MESSAGE, _encoding)
                ),
                bytes(MESSAGE, _encoding)
            )
    else:
        assert _multi_hash(

                signed_hashes=(
                    (
                        +1,
                        bytes(MESSAGE, _encoding)
                    ),
                    (
                        +1,
                        bytes(MESSAGE, _encoding)
                    ),
                    (
                        +1,
                        bytes(MESSAGE, _encoding)
                    ),
                    (
                        '_anything_',
                        bytes(MESSAGE, _encoding)
                    )
                ),
                start=0

        ) == _hash(
                _hash(
                    _hash('%s%s' % (MESSAGE, MESSAGE)),
                    bytes(MESSAGE, _encoding)
                ),
                bytes(MESSAGE, _encoding)
            )


@pytest.mark.parametrize('_machine', _machines)
def test_4_elems_multi_hash_edge_case_2(_machine):

    _hash       = _machine.hash
    _multi_hash = _machine.multi_hash
    _encoding   = _machine.ENCODING

    if _machine.SECURITY:

        assert _multi_hash(

                signed_hashes=(
                    (
                        '_anything_',
                        bytes(MESSAGE, _encoding)
                    ),
                    (
                        -1,
                        bytes(MESSAGE, _encoding)
                    ),
                    (
                        -1,
                        bytes(MESSAGE, _encoding)
                    ),
                    (
                        -1,
                        bytes(MESSAGE, _encoding)
                    )
                ),
                start=3

            ) == _hash(
                    bytes(MESSAGE, _encoding),
                    _hash(
                        bytes(MESSAGE, _encoding),
                        _hash(
                            bytes(MESSAGE, _encoding),
                            bytes(MESSAGE, _encoding)
                        )
                    )
                )
    else:
        assert _multi_hash(

                signed_hashes=(
                    (
                        '_anything_',
                        bytes(MESSAGE, _encoding)
                    ),
                    (
                        -1,
                        bytes(MESSAGE, _encoding)
                    ),
                    (
                        -1,
                        bytes(MESSAGE, _encoding)
                    ),
                    (
                        -1,
                        bytes(MESSAGE, _encoding)
                    )
                ),
                start=3

            ) == _hash(
                    bytes(MESSAGE, _encoding),
                    _hash(
                        bytes(MESSAGE, _encoding),
                        _hash('%s%s' % (MESSAGE, MESSAGE))
                    )
                )


@pytest.mark.parametrize('_machine', _machines)
def test_4_elems_multi_hash(_machine):

    _hash       = _machine.hash
    _multi_hash = _machine.multi_hash
    _encoding   = _machine.ENCODING

    if _machine.SECURITY:

        assert _multi_hash(

                signed_hashes=(
                    (
                        +1,
                        bytes(MESSAGE, _encoding)
                    ),
                    (
                        +1,
                        bytes(MESSAGE, _encoding)
                    ),
                    (
                        -1,
                        bytes(MESSAGE, _encoding)
                    ),
                    (
                        -1,
                        bytes(MESSAGE, _encoding)
                    )
                ),
                start=1

        ) == _hash(
                _hash(
                    bytes(MESSAGE, _encoding),
                    _hash(
                        bytes(MESSAGE, _encoding),
                        bytes(MESSAGE, _encoding))
                    ),
                bytes(MESSAGE, _encoding)
            )
    else:
        assert _multi_hash(

                signed_hashes=(
                    (
                        +1,
                        bytes(MESSAGE, _encoding)
                    ),
                    (
                        +1,
                        bytes(MESSAGE, _encoding)
                    ),
                    (
                        -1,
                        bytes(MESSAGE, _encoding)
                    ),
                    (
                        -1,
                        bytes(MESSAGE, _encoding)
                    )
                ),
                start=1

        ) == _hash(
                _hash(
                    bytes(MESSAGE, _encoding),
                    _hash('%s%s' % (MESSAGE, MESSAGE))
                ),
                bytes(MESSAGE, _encoding)
            )
