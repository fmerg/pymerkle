"""
Hashing machinery and supported hash functions.
"""

import hashlib


SHA2_ALGORITHMS = ['sha224', 'sha256', 'sha384', 'sha512']
SHA3_ALGORITHMS = ['sha3_224', 'sha3_256', 'sha3_384', 'sha3_512']
KECCAK_ALGORITHMS = ['keccak_224', 'keccak_256', 'keccak_384', 'keccak_512']


# Supported hash functions by name; keccak ones only if the keccak extra
# (safe-pysha3, providing the sha3 module) is installed
HASH_FUNCTIONS = {name: getattr(hashlib, name) for name in
    SHA2_ALGORITHMS + SHA3_ALGORITHMS}
try:
    import sha3
except ImportError:
    pass
else:
    HASH_FUNCTIONS.update({name: getattr(sha3, name) for name in
        KECCAK_ALGORITHMS})

ALGORITHMS = list(HASH_FUNCTIONS)


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
        if normalized not in ALGORITHMS:
            msg = f'{algorithm} not supported'
            if normalized in KECCAK_ALGORITHMS:
                msg += ': You need to install pymerkle[keccak]'
            raise ValueError(msg)
        self.algorithm = normalized
        self.hashfunc = HASH_FUNCTIONS[normalized]

        self.security = security
        self.leaf_prefix = b'\x00' if self.security else b''
        self.node_prefix = b'\x01' if self.security else b''


    def hash_empty(self):
        """
        Computes the hash of the empty data without prepending security
        prefixes.

        :rtype: bytes
        """
        return self.hashfunc(b'').digest()


    def hash_raw(self, data):
        """
        Computes the hash of the provided data without prepending security
        prefixes.

        :type data: bytes
        :rtype: bytes
        """
        return self.hashfunc(data).digest()


    def hash_buff(self, data):
        """
        Computes the hash of the provided binary data.

        .. note:: Prepends ``\\x00`` if security mode is enabled

        :type data: bytes
        :rtype: bytes
        """
        return self.hashfunc(self.leaf_prefix + data).digest()


    def hash_pair(self, left, right):
        """
        Computes the hash of the concatenation of the provided binary data.

        .. note:: Prepends ``\\x01`` if security mode is enabled

        :param left: left digest
        :type left: bytes
        :param right: right digest
        :type right: bytes
        :rtype: bytes
        """
        return self.hashfunc(self.node_prefix + left + right).digest()


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
