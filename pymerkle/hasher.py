import hashlib
from pymerkle import constants


class MerkleHasher:
    """
    Encapsulates elementary hashing operations.

    :param algorithm: hash algorithm
    :type algorithm: str
    :param security: [optional] defense against second-preimage attack. Defaults
        to *True*
    :type security: bool
    """

    def __init__(self, algorithm, security=True, **kw):
        normalized = algorithm.lower().replace('-', '_')

        if normalized not in constants.ALGORITHMS:
            raise ValueError(f'{algorithm} not supported')

        self.prefx00 = b'\x00' if security else b''
        self.prefx01 = b'\x01' if security else b''

        self.algorithm = algorithm
        self.security = security
        self.hashfunc = getattr(hashlib, algorithm)


    def _consume_bytes(self, buff):
        """
        :param buff:
        :type buff: bytes
        :rtype: bytes
        """
        hasher = self.hashfunc()
        update = hasher.update
        chunksize = 1024
        offset = 0
        chunk = buff[offset: chunksize]
        while chunk:
            update(chunk)
            offset += chunksize
            chunk = buff[offset: offset + chunksize]

        return hasher.digest()


    def hash_empty(self):
        """
        Computes the hash of the empty data without prepending security
        prefixes.

        :param buff:
        :type buff: bytes
        :rtype: bytes
        """
        return self._consume_bytes(b'')


    def hash_raw(self, buff):
        """
        Computes the hash of the provided data without prepending security
        prefixes.

        :param buff:
        :type buff: bytes
        :rtype: bytes
        """
        return self._consume_bytes(buff)


    def hash_buff(self, data):
        """
        Computes the hash of the provided binary data.

        .. note:: Prepends ``\\x00`` if security mode is enabled

        :type data: bytes
        :rtype: bytes
        """
        return self._consume_bytes(self.prefx00 + data)



    def hash_pair(self, buff1, buff2):
        """
        Computes the hash of the concatenation of the provided binary data.

        .. note:: Prepends ``\\x01`` if security mode is enabled

        :param buff1: left value
        :type buff1: bytes
        :param buff2: right value
        :type buff2: bytes
        :rtype: bytes
        """
        return self.hashfunc(self.prefx01 + buff1 + buff2).digest()
