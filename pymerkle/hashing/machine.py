"""
Provides hash utilities used accross the *pymerkle* library
"""

import hashlib
from .encoding import Encoder
from pymerkle.exceptions import UnsupportedHashType, EmptyPathException


HASH_TYPES = ['md5', 'sha224', 'sha256', 'sha384', 'sha512',
    'sha3_224', 'sha3_256', 'sha3_384', 'sha3_512',]
"""Supported hash types"""


class HashMachine(Encoder):
    """
    Encapsulates the hash utilities used accross the *pymerkle* library

    :param hash_type: [optional] Specifies the hash algorithm used by the
            machine. Defaults to *sha256*.
    :type hash_type: str
    :param encoding: [optional] Specifies the encoding algorithm used by the
            machine before hashing. Defaults to *utf_8*.
    :type encoding: str
    :param raw_bytes: [optional] Specifies whether the machine accepts raw
            binary data independently of its configured encoding type.
            Defaults to *True*.
    :type raw_bytes: bool
    :param security: [optional] Specifies whether defense against
            second-preimage attack will be enabled. Defaults to *True*.
    :type security: bool

    :raises UnsupportedHashType: if the provided encoding is not
                        contained in *pymerkle.hashing.encoding.ENCODINGS*.
    :raises UnsupportedHashType: if the provided hash-type is not
                        contained in *pymerkle.hashing.machine.HASH_TYPES*.

    :ivar algorithm: (*builtin_function_or_method*) Hash algorithm used
                    by the machine
    :ivar encoding: (*str*) See the constructor's homonymous argument
    :ivar raw_bytes: (*bool*) See the constructor's homonymous argument
    :ivar security: (*bool*) See the constructor's homonymous argument
    """
    def __init__(self, hash_type='sha256', encoding='utf-8',
                    raw_bytes=True, security=True):
        ht = hash_type.lower().replace('-', '_')
        if ht not in HASH_TYPES:
            err = f'Hash type {hash_type} is not supported'
            raise UnsupportedHashType(err)
        self.hash_type = ht
        self.algorithm = getattr(hashlib, self.hash_type)
        super().__init__(encoding=encoding, raw_bytes=raw_bytes, security=security)


    def hash(self, left, right=None):
        """
        Core hash utility

        Computes the digest of the provided arguments' concatenation. If only
        one argument is passed in, then the disgest of this single argument
        is computed.

        :param left: left member of the pair to be hashed
        :type left: str or bytes
        :param right: [optional] right member of the pair to be hashed
        :type right: bytes

        :returns: Digest of the entity occuring after concatenation of
                provided arguments
        :rtype: bytes
        """
        data = self.encode(left, right)
        hexdigest = self.algorithm(data).hexdigest()
        return bytes(hexdigest, self.encoding)


    def multi_hash(self, signed_hashes, start):
        """
        Extended hash utility

        Repeatedly applies the *.hash()* method over the provided iterable of
        signed hashes (signs indicating parenthetization during repetition and
        *start* indicating starting position of application).
        Schematically speaking,

        ``multi_hash([(1, a), (1, b), (-1, c), (-1, d)], 1)``

        is equivalent to

        ``hash(hash(a, hash(b, c)), d)``.

        .. note:: If the provided iterable contains only one element, then this
            single hash is returned (without sign), that is,

                 ``multi_hash(signed_hashes=((+/-1, a)), start=0)``

            equals ``a`` (no hashing over single elements)

        .. warning:: When using this method, make sure that the combination of
                signs corresponds indeed to a valid parenthetization

        :param signed_hashes: a finite sequence of signed hashes
        :type signed_hashes: iterable of (+1/-1, bytes)
        :param start: starting position for application of *.hash()*
        :type start: int
        :rtype: bytes

        :raises EmptyPathException: if the provided sequence was empty
        """
        hash = self.hash

        signed_hashes = list(signed_hashes)
        if signed_hashes == []:
            raise EmptyPathException
        elif len(signed_hashes) == 1:
            return signed_hashes[0][1]

        i = start
        while len(signed_hashes) > 1:
            if signed_hashes[i][0] == +1:           # Pair with the right neighbour
                if i == 0:
                    new_sign = +1
                else:
                    new_sign = signed_hashes[i + 1][0]
                new_hash = hash(
                    signed_hashes[i][1],
                    signed_hashes[i + 1][1])
                move = +1
            else:                                   # Pair with the left neighbour
                new_sign = signed_hashes[i - 1][0]
                new_hash = hash(
                    signed_hashes[i - 1][1],
                    signed_hashes[i][1])
                move = -1
            signed_hashes[i] = (new_sign, new_hash)
            del signed_hashes[i + move]             # Shrink
            if move < 0:
                i -= 1
        return signed_hashes[0][1]
