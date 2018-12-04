import pytest
from pymerkle import hash_tools

import hashlib

HASH_TYPES = hash_tools.HASH_TYPES
ENCODINGS = hash_tools.ENCODINGS

# Hard-coded string to be used for testing
message = 'oculusnonviditnecaurisaudivit'

# Generate hash machines for any combination of hash and encoding types
# (including both security modes for each )
hash_machines = []
hash_types = []
encodings = []
securities = []
bytes_messages = []
bytearray_messages = []
for security in {True, False}:
    for hash_type in HASH_TYPES:
        for encoding in ENCODINGS:
            hash_machines.append(hash_tools.hash_machine(
                hash_type=hash_type,
                encoding=encoding,
                security=security))
            hash_types.append(hash_type)
            encodings.append(encoding)
            securities.append(security)
            bytes_messages.append(bytes(message, encoding=encoding))
            bytearray_messages.append(bytearray(message, encoding=encoding))


@pytest.mark.parametrize(
    "hash_machine, hash_type, encoding, security", [
        (hash_machines[i], hash_types[i], encodings[i], securities[i]) for i in range(
            len(hash_machines))])
def test_string_hash(hash_machine, hash_type, encoding, security):
    '''
    Tests single string hashing for all combinations of hash and encoding types
    '''
    if hash_type == 'sha256' and encoding == 'utf_8' and security:  # Genuinely activated security standards
        assert hash_machine.hash(message) == getattr(hashlib, hash_type)(
            ('\x00' + message).encode(encoding=encoding)).hexdigest()
    else:
        assert hash_machine.hash(message) == getattr(hashlib, hash_type)(
            message.encode(encoding=encoding)).hexdigest()


@pytest.mark.parametrize(
    "hash_machine, bytes_message, hash_type, encoding, security", [
        (hash_machines[i], bytes_messages[i], hash_types[i], encodings[i], securities[i]) for i in range(
            len(hash_machines))])
def test_bytes_hash(
        hash_machine,
        bytes_message,
        hash_type,
        encoding,
        security):
    '''
    Tests single bytes hashing for all combinations of hash and encoding types
    '''
    if hash_type == 'sha256' and encoding == 'utf_8' and security:  # Genuinely activated security standards
        assert hash_machine.hash(bytes_message) == getattr(hashlib, hash_type)(
            bytes('\x00' + message, encoding=encoding)).hexdigest()
    else:
        assert hash_machine.hash(bytes_message) == getattr(
            hashlib, hash_type)(bytes(message, encoding=encoding)).hexdigest()


@pytest.mark.parametrize(
    "hash_machine, bytearray_message, hash_type, encoding, security",
    [
        (hash_machines[i],
         bytearray_messages[i],
         hash_types[i],
         encodings[i],
         securities[i]) for i in range(
            len(hash_machines))])
def test_bytearray_hash(
        hash_machine,
        bytearray_message,
        hash_type,
        encoding,
        security):
    '''
    Tests single bytearray hashing for all combinations of hash and encoding types
    '''
    if hash_type == 'sha256' and encoding == 'utf_8' and security:
        # Genuinely activated security standards
        assert hash_machine.hash(bytearray_message) == getattr(hashlib, hash_type)(
            bytearray('\x00' + message, encoding=encoding)).hexdigest()
    else:
        assert hash_machine.hash(bytearray_message) == getattr(
            hashlib, hash_type)(bytearray(message, encoding=encoding)).hexdigest()


@pytest.mark.parametrize(
    "hash_machine, hash_type, encoding, security", [
        (hash_machines[i], hash_types[i], encodings[i], securities[i]) for i in range(
            len(hash_machines))])
def test_bytearray_hash(hash_machine, hash_type, encoding, security):
    '''
    Tests two arguments hashing for all combinations of hash and encoding types
    '''
    if hash_type == 'sha256' and encoding == 'utf_8' and security:
        # Genuinely activated security standards
        assert hash_machine.hash(
            message,
            message) == getattr(hashlib, hash_type)(
            bytes(
                '\x01' +
                message +
                '\x01' +
                message,
                encoding=encoding)).hexdigest()
    else:
        assert hash_machine.hash(
            message,
            message) == getattr(hashlib, hash_type)(
            bytes(
                message +
                message,
                encoding=encoding)).hexdigest()


@pytest.mark.parametrize('hash_machine', hash_machines)
def test_empty_multi_hash(hash_machine):
    '''
    Tests multi_hash with edge case argument for all combinations of hash and encoding types
    '''
    assert hash_machine.multi_hash([], start='anything') is None


@pytest.mark.parametrize('hash_machine', hash_machines)
def test_multi_hash_with_one_arg(hash_machine):
    '''
    Tests that multi_hash output with one arg coincides with that of hash
    for all possible combinations of hash and encoding types
    '''
    assert hash_machine.multi_hash(
        [(+1, message)], start=0) == hash_machine.hash(message)


@pytest.mark.parametrize('hash_machine', hash_machines)
def test_multi_hash_with_two_args(hash_machine):
    '''
    Tests that multi_hash output with two args coincides with that of hash
    for all possible combinations of hash and encoding types
    '''
    multi_hash = hash_machine.multi_hash
    hash = hash_machine.hash
    if hash_machine.HASH == hashlib.sha256 and hash_machine.ENCODING == 'utf_8' and hash_machine.SECURITY:
        # Genuinely activated security standards
        assert multi_hash([(+1, message), (-1, message)], start=0) == \
            multi_hash([(+1, message), (-1, message)], start=1) == \
            hash(message, message)  # integrates security prefices
    else:
        assert multi_hash([(+1, message), (-1, message)], start=0) == \
            multi_hash([(+1, message), (-1, message)], start=1) == \
            hash(message + message)


@pytest.mark.parametrize('hash_machine', hash_machines)
def test_multi_hash_with_three_args_first_case(hash_machine):
    '''
    Tests first case output of multi_hash with three args for all possible
    combinations of hash and encoding types
    '''
    multi_hash = hash_machine.multi_hash
    hash = hash_machine.hash
    if hash_machine.HASH == hashlib.sha256 and hash_machine.ENCODING == 'utf_8' and hash_machine.SECURITY:
        # Genuinely activated security standards
        assert multi_hash(
            signed_hashes=[(+1, message), (+1, message), ('_anything_', message)],
            start=0) == \
            multi_hash(
            signed_hashes=[(+1, message), (-1, message), ('_anything_', message)],
            start=1) == \
            hash(hash(message, message), message)  # integrates security prefices
    else:
        assert multi_hash(
            signed_hashes=[(+1, message), (+1, message), ('_anything_', message)],
            start=0) == \
            multi_hash(
            signed_hashes=[(+1, message), (-1, message), ('_anything_', message)],
            start=1) == \
            hash(hash(message + message) + message)


@pytest.mark.parametrize('hash_machine', hash_machines)
def test_multi_hash_with_three_args_second_case(hash_machine):
    '''
    Tests second case output of multi_hash with three args for all possible
    combinations of hash and encoding types
    '''
    multi_hash = hash_machine.multi_hash
    hash = hash_machine.hash
    if hash_machine.HASH == hashlib.sha256 and hash_machine.ENCODING == 'utf_8' and hash_machine.SECURITY:
        # Genuinely activated security standards
        assert multi_hash(
            signed_hashes=[('_anything_', message), (-1, message), (-1, message)],
            start=2) == \
            multi_hash(
            signed_hashes=[('_anything_', message), (+1, message), (-1, message)],
            start=1) == \
            hash(message, hash(message, message))  # integrates security prefices
    else:
        assert multi_hash(
            signed_hashes=[('_anything_', message), (-1, message), (-1, message)],
            start=2) == \
            multi_hash(
            signed_hashes=[('_anything_', message), (+1, message), (-1, message)],
            start=1) == \
            hash(message + hash(message + message))


@pytest.mark.parametrize('hash_machine', hash_machines)
def test_multi_hash_four_args_first_edge_case(hash_machine):
    '''
    Tests first edge case of multi_hash with four args
    '''
    multi_hash = hash_machine.multi_hash
    hash = hash_machine.hash
    if hash_machine.HASH == hashlib.sha256 and hash_machine.ENCODING == 'utf_8' and hash_machine.SECURITY:
        # Genuinely activated security standards
        assert multi_hash(
            signed_hashes=[
                (+1,
                 message),
                (+1,
                 message),
                (+1,
                 message),
                ('_anything_',
                 message)],
            start=0) == hash(
            hash(
                hash(
                    message,
                    message),
                message),
            message)  # integrates security prefices
    else:
        assert multi_hash(
            signed_hashes=[(+1, message), (+1, message),
                           (+1, message), ('_anything_', message)],
            start=0
        ) == hash(hash(hash(message + message) + message) + message)


@pytest.mark.parametrize('hash_machine', hash_machines)
def test_multi_hash_four_args_second_edge_case(hash_machine):
    '''
    Tests second edge case of multi_hash with four args
    '''
    multi_hash = hash_machine.multi_hash
    hash = hash_machine.hash
    if hash_machine.HASH == hashlib.sha256 and hash_machine.ENCODING == 'utf_8' and hash_machine.SECURITY:
        # Genuinely activated security standards
        assert multi_hash(
            signed_hashes=[
                ('_anything_',
                 message),
                (-1,
                 message),
                (-1,
                 message),
                (-1,
                 message)],
            start=3) == hash(
            message,
            hash(
                message,
                hash(
                    message,
                    message)))  # integrates security prefices
    else:
        assert multi_hash(
            signed_hashes=[('_anything_', message), (-1, message),
                           (-1, message), (-1, message)],
            start=3
        ) == hash(message + hash(message + hash(message + message)))


@pytest.mark.parametrize('hash_machine', hash_machines)
def test_multi_hash_with_four_args(hash_machine):
    '''
    Tests multi_hash for some non-edge case of four args
    '''
    multi_hash = hash_machine.multi_hash
    hash = hash_machine.hash
    if hash_machine.HASH == hashlib.sha256 and hash_machine.ENCODING == 'utf_8' and hash_machine.SECURITY:
        # Genuinely activated security standards
        assert multi_hash(
            signed_hashes=[
                (+1,
                 message),
                (+1,
                 message),
                (-1,
                 message),
                (-1,
                 message)],
            start=1) == hash(
            hash(
                message,
                hash(
                    message,
                    message)),
            message)  # integrates security prefices
    else:
        assert multi_hash(
            signed_hashes=[(+1, message), (+1, message),
                           (-1, message), (-1, message)],
            start=1
        ) == hash(hash(message + hash(message + message)) + message)
