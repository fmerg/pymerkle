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


class EmptyPathException(Exception):
    """
    Raised when an empty path of hashes is fed to a hashing engine
    """
    pass


class HashEngine:
    """
    :param algorithm: [optional] hash algorithm (defaults to *sha256*)
    :type algorithm: str
    :param encoding: [optional] encoding type (defaults to *utf-8*)
    :type encoding: str
    :param security: [optional] defence against 2nd-preimage attack (default:
        true)
    :type security: bool

    :raises UnsupportedParameter: if the provided algorithm or encoding is not
        supported.
    """

    def __init__(self, algorithm='sha256', encoding='utf-8', security=True):

        for (attr, provided, supported) in (
                ('algorithm', algorithm, ALGORITHMS),
                ('encoding', encoding, ENCODINGS)):

            normalized = provided.lower().replace('-', '_')
            if normalized not in supported:
                raise UnsupportedParameter(f'{provided} is not supported')

            setattr(self, attr, normalized)

        self.security = security

        self.prefx00 = '\x00'.encode(encoding) if security else bytes()
        self.prefx01 = '\x01'.encode(encoding) if security else bytes()

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
        Computes the digest occuring after repeatedly applying *hash_pair()*
        over the provided path of hashes, where signs indicate parenthetization
        in terms of pairing and *offset* is the starting position counting from
        zero. Schematically speaking,

        ``hash_path([(1, a), (1, b), (-1, c), (-1, d)], 1)``

        is equivalent to

        ``hash(hash(a, hash(b, c)), d)``.

        .. warning:: Make sure that the combination of signs corresponds to
            a valid parenthetization.

        :param path: path of hashes
        :type path: iterable of (+1/-1, bytes)
        :param offset: starting position of hashing
        :type offset: int
        :rtype: bytes

        :raises EmptyPathException: if the provided path of hashes is empty.
        """
        path = list(path)

        if not path:
            raise EmptyPathException
        elif len(path) == 1:
            return path[0][1]

        i = offset
        while len(path) > 1:

            if path[i][0] == +1:
                # Pair with the right neighbour
                if i != 0:
                    sign = path[i + 1][0]
                else:
                    sign = +1

                digest = self.hash_pair(path[i][1], path[i + 1][1])
                move = +1
            else:
                # Pair with left neighbour
                sign = path[i - 1][0]
                digest = self.hash_pair(path[i - 1][1], path[i][1])
                move = -1

            path[i] = (sign, digest)

            del path[i + move]
            if move < 0:
                i -= 1

        return path[0][1]
