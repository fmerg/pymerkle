import pytest
from pymerkle import hashing
from pymerkle.exceptions import EmptyPathException

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


# --------------------------- .multi_hash() testing ---------------------------


@pytest.mark.parametrize('_machine', _machines)
def test_0_elems_multi_hash(_machine):
    """Tests that the EmptyPathException is raised then the .multi_hash() method
    is called with an empty first argument
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
