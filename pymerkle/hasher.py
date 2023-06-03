"""
Hashing machinery for data insertion and proof verification
"""

import hashlib
from pymerkle import constants


class UnsupportedParameter(Exception):
    """
    Raised when a Merkle-hasher with unsupported parameters is requested
    """
    pass


class MerkleHasher:
    """
    :param algorithm: hash algorithm
    :type algorithm: str
    :param security: [optional] defense against 2nd-preimage attack. Defaults
        to *True*
    :type security: bool
    """

    def __init__(self, algorithm, security=True, **kw):
        normalized = algorithm.lower().replace('-', '_')
        if normalized not in constants.ALGORITHMS:
            raise UnsupportedParameter('%s is not supported' % algorithm)

        self.algorithm = algorithm
        self.security = security
        self.prefx00 = b'\x00' if security else b''
        self.prefx01 = b'\x01' if security else b''


    def consume(self, buff):
        """
        Computes the raw hash of the provided input

        :param buff:
        :type buff: bytes
        :rtype: bytes
        """
        _hasher = getattr(hashlib, self.algorithm)()

        update = _hasher.update
        chunksize = 1024
        offset = 0
        chunk = buff[offset: chunksize]
        while chunk:
            update(chunk)
            offset += chunksize
            chunk = buff[offset: offset + chunksize]

        return _hasher.digest()


    def hash_entry(self, data):
        """
        Computes the hash of the provided data

        .. note:: Prepends ``\\x00`` if security mode is enabled

        :type data: bytes
        :rtype: bytes
        """
        buff = self.prefx00 + data

        return self.consume(buff)


    def hash_nodes(self, left, right):
        """
        Computes the hash of the concatenation of the provided values

        .. note:: Prepends ``\\x01`` if security mode is enabled

        :param left: first value
        :type left: bytes
        :param right: second value
        :type right: bytes
        :rtype: bytes
        """
        buff = self.prefx01 + left + right

        return self.consume(buff)
