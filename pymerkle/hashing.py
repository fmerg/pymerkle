"""
Hashing machinery for data insertion and proof verification
"""

import hashlib
from pymerkle.constants import ENCODINGS, ALGORITHMS


class UnsupportedParameter(Exception):
    """
    Raised when a hashing engine with unsupported parameters is requested
    """
    pass


class HashEngine:
    """
    :param algorithm: [optional] hash algorithm (defaults to *sha256*)
    :type algorithm: str
    :param encoding: [optional] encoding type (defaults to *utf-8*)
    :type encoding: str
    :param security: [optional] defence against 2nd-preimage attack (default:
        *True*)
    :type security: bool
    """

    def __init__(self, algorithm='sha256', encoding='utf-8', security=True):
        algorith, encoding = self.validate_parameters(algorithm, encoding)

        self.algorithm = algorithm
        self.encoding = encoding
        self.security = security

        self.prefx00 = '\x00'.encode(encoding) if security else bytes()
        self.prefx01 = '\x01'.encode(encoding) if security else bytes()


    @staticmethod
    def validate_parameters(algorithm, encoding):
        validated = []
        for (provided, supported) in (
            (algorithm, ALGORITHMS),
            (encoding, ENCODINGS)
        ):
            normalized = provided.lower().replace('-', '_')
            if normalized not in supported:
                raise UnsupportedParameter('%s is not supported' % provided)

            validated += [normalized]

        return validated


    def consume(self, buffer):
        """
        Returns the hash digest of the provided input

        :param buffer:
        :type buffer: bytes
        :rtype: bytes
        """
        hasher = getattr(hashlib, self.algorithm)()

        update = hasher.update
        chunksize = 1024
        offset = 0
        chunk = buffer[offset: chunksize]
        while chunk:
            update(chunk)
            offset += chunksize
            chunk = buffer[offset: offset + chunksize]

        checksum = hasher.hexdigest()

        return checksum.encode(self.encoding)


    def hash_entry(self, data):
        """
        Compute the hash of the provided data

        .. attention:: Prepends ``\\x00`` if security mode is enabled

        :type data: bytes or str
        :rtype: bytes
        """
        if not isinstance(data, bytes):
            data = data.encode(self.encoding)

        buffer = self.prefx00 + data
        digest = self.consume(buffer)

        return digest


    def hash_pair(self, left, right):
        """
        Compute the hash of the concatenation of the provided values

        .. note:: Prepends ``\\x01`` to each argument if security mode is
            enabled

        :param left: first value
        :type left: bytes
        :param right: second value
        :type right: bytes
        :rtype: bytes
        """
        buffer = self.prefx01 + left + self.prefx01 + right
        digest = self.consume(buffer)

        return digest


    def hash_path(self, path, offset):
        """
        Compute the hash occuring after repeatedly pairing over the provided
        path of hashes starting from the provided position.

        Signs indicate parenthetization for pairing. Schematically speaking,

        ``hash_path([(+1, a), (+1, b), (-1, c), (-1, d)], 1)``

        is equivalent to

        ``hash(hash(a, hash(b, c)), d)``

        .. attention:: Make sure that the combination of signs corresponds to
            a valid parenthetization

        :param path: path of hashes
        :type path: iterable of (+1/-1, bytes)
        :param offset: starting position counting from zero
        :type offset: int
        :rtype: bytes

        .. note:: Returns *None* in case of empty path
        """
        path = list(path)

        if not path:
            return None

        elif len(path) == 1:
            return path[0][1]

        i = offset
        hash_pair = self.hash_pair
        while len(path) > 1:
            if path[i][0] == +1:
                if i != 0:
                    sign = path[i + 1][0]
                else:
                    sign = +1
                value = hash_pair(path[i][1], path[i + 1][1])
                move = +1
            else:
                sign = path[i - 1][0]
                value = hash_pair(path[i - 1][1], path[i][1])
                move = -1

            path[i] = (sign, value)
            del path[i + move]
            if move < 0:
                i -= 1

        return path[0][1]
