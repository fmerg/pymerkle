from pymerkle import constants


class MerkleHasher:
    """
    Encapsulates elementary hashing operations.

    :param algorithm: hash algorithm
    :type algorithm: str
    :param security: [optional] resistance against second-preimage attack. Defaults
        to *True*
    :type security: bool
    """

    def __init__(self, algorithm, security=True):
        normalized = algorithm.lower().replace('-', '_')
        if normalized not in constants.ALGORITHMS:
            msg = f'{algorithm} not supported'
            if normalized in constants.KECCAK_ALGORITHMS:
                msg += ': You need to install pysha3'
            raise ValueError(msg)
        self.algorithm = normalized
        self.hashfunc = constants.HASH_FUNCTIONS[normalized]

        self.security = security
        self.prefx00 = b'\x00' if self.security else b''
        self.prefx01 = b'\x01' if self.security else b''


    def hash_empty(self):
        """
        Computes the hash of the empty data without prepending security
        prefixes.

        :rtype: bytes
        """
        return self.hashfunc(b'').digest()


    def hash_raw(self, buff):
        """
        Computes the hash of the provided data without prepending security
        prefixes.

        :param buff:
        :type buff: bytes
        :rtype: bytes
        """
        return self.hashfunc(buff).digest()


    def hash_buff(self, data):
        """
        Computes the hash of the provided binary data.

        .. note:: Prepends ``\\x00`` if security mode is enabled

        :type data: bytes
        :rtype: bytes
        """
        return self.hashfunc(self.prefx00 + data).digest()


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


    def hash_fold(self, digests):
        """
        Combines the provided digests from right to left, i.e., computes
        ``hash_pair(d_n, ... hash_pair(d_2, d_1))`` for digests ``d_1, ...,
        d_n`` given in this order. This is how the root-hash of a tree is
        obtained from the roots of its maximal perfect subtrees.

        :param digests: non-empty sequence of digests ordered from right to
            left
        :type digests: list[bytes]
        :rtype: bytes
        """
        result = digests[0]
        for digest in digests[1:]:
            result = self.hash_pair(digest, result)

        return result
