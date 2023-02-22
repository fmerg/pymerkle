"""
Hashing machinery for data insertion and proof verification
"""

import hashlib
from pymerkle.constants import ENCODINGS, ALGORITHMS


class UnsupportedParameter(Exception):
    """
    Raised when a hashing engine with unsupported parameters is requested.
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
                raise UnsupportedParameter(f'{provided} is not supported')

            validated += [normalized]

        return validated


    def load_hasher(self):

        return getattr(hashlib, self.algorithm)()

    def hash_entry(self, data):
        """
        Compute the hash of the provided data

        .. attention:: Preprends ``\\x00`` if security mode is enabled

        :type data: bytes or str
        :rtype: bytes
        """
        buff = self.prefx00 + (data if isinstance(data, bytes) else
                               data.encode(self.encoding))

        hasher = self.load_hasher()
        update = hasher.update
        offset = 0
        chunksize = 1024
        chunk = buff[offset: chunksize]
        while chunk:
            update(chunk)
            offset += chunksize
            chunk = buff[offset: offset + chunksize]

        return hasher.hexdigest().encode(self.encoding)

    def hash_pair(self, left, right):
        """
        Compute the hash of the concatenation of the provided arguments

        .. attention:: Preprends ``\\x01`` if security mode is enabled

        :type left: bytes
        :type right: bytes
        :rtype: bytes
        """
        buff = self.prefx01 + left + self.prefx01 + right

        hasher = self.load_hasher()
        hasher.update(buff)

        return hasher.hexdigest().encode(self.encoding)

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
        while len(path) > 1:
            if path[i][0] == +1:
                if i != 0:
                    sign = path[i + 1][0]
                else:
                    sign = +1
                value = self.hash_pair(path[i][1], path[i + 1][1])
                move = +1
            else:
                sign = path[i - 1][0]
                value = self.hash_pair(path[i - 1][1], path[i][1])
                move = -1

            path[i] = (sign, value)
            del path[i + move]
            if move < 0:
                i -= 1

        return path[0][1]
