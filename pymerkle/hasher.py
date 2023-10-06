import hashlib
from typing import Callable, Literal

from typing_extensions import Buffer

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
    algorithm: str
    security: bool
    prefx00: Literal[b"\x00", b""]
    prefx01: Literal[b"\x01", b""]
    hashfunc: Callable[[bytes,], 'hashlib._Hash']

    def __init__(self, algorithm: str, security: bool = True, **kw) -> None:
        normalized: str = algorithm.lower().replace('-', '_')
        if normalized not in constants.ALGORITHMS:
            msg: str = f'{algorithm} not supported'
            if normalized in constants.KECCAK_ALGORITHMS:
                msg += ': You need to install pysha3'
            raise ValueError(msg)
        self.algorithm = algorithm

        module = hashlib
        if normalized in constants.KECCAK_ALGORITHMS:
            import sha3
            module = sha3
        self.hashfunc = getattr(module, self.algorithm)

        self.security = security
        self.prefx00 = b'\x00' if self.security else b''
        self.prefx01 = b'\x01' if self.security else b''

    def _consume_bytes(self, buff: bytes) -> bytes:
        """
        :param buff:
        :type buff: bytes
        :rtype: bytes
        """
        hasher: hashlib._Hash = self.hashfunc()  # type: ignore
        update: Callable[[Buffer], None] = hasher.update
        chunksize: Literal[1024] = 1024
        offset: int = 0
        chunk: bytes = buff[offset: chunksize]
        while chunk:
            update(chunk)
            offset += chunksize
            chunk = buff[offset: offset + chunksize]

        return hasher.digest()

    def hash_empty(self) -> bytes:
        """
        Computes the hash of the empty data without prepending security
        prefixes.

        :param buff:
        :type buff: bytes
        :rtype: bytes
        """
        return self._consume_bytes(buff=b'')

    def hash_raw(self, buff: bytes) -> bytes:
        """
        Computes the hash of the provided data without prepending security
        prefixes.

        :param buff:
        :type buff: bytes
        :rtype: bytes
        """
        return self._consume_bytes(buff=buff)

    def hash_buff(self, data: bytes) -> bytes:
        """
        Computes the hash of the provided binary data.

        .. note:: Prepends ``\\x00`` if security mode is enabled

        :type data: bytes
        :rtype: bytes
        """
        return self._consume_bytes(buff=self.prefx00 + data)

    def hash_pair(self, buff1: bytes, buff2: bytes) -> bytes:
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
