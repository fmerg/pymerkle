"""
Provides hash utilities used accross the *pymerkle* library
"""
import hashlib
from pymerkle.exceptions import UnsupportedHashType, EmptyPathException
from .encoding import Encoder


HASH_TYPES = ['md5', 'sha224', 'sha256', 'sha384', 'sha512',
    'sha3_224', 'sha3_256', 'sha3_384', 'sha3_512',]
"""Supported hash types"""


class HashMachine(Encoder):
    """
    Encapsulates the hash utilities used accross the *pymerkle* library

    :param hash_type: Defaults to ``'sha256'``. Specifies the hash algorithm to
        be used by the machine. Must be among the elements of ``HASH_TYPES``
    :type hash_type: str
    :param encoding: Defaults to ``'utf_8'``. Specifies the encoding algorithm
        to be used by the machine before hashing. Must be among the elements of
        ``encoder.ENCODINGS`` (upper- or mixed-case with '-' instead of
        '_' allowed).
    :type encoding: str
    :param raw_bytes: Defaults to ``False``. Specifies whether the machine
        accepts raw binary data independently of its configured encoding type
    :type raw_bytes: bool
    :param security: Defaults to ``True``. Specifies whether single, resp.
        double arguments passed into the ``.hash()`` function will be prepended
        with ``'0x00'``, resp. ``'0x01'`` before hashing)
    :type security: bool

    :raises UnsupportedHashType: if the provided ``encoding`` is not
                        contained in ``encoder.ENCODINGS``
    :raises UnsupportedHashType: if the provided ``hash_type`` is not
                        contained in ``hashing.machine.HASH_TYPES``

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
            err = 'Hash type %s is not supported' % hash_type
            raise UnsupportedHashType(err)
        self.hash_type = ht
        self.algorithm = getattr(hashlib, self.hash_type)
        super().__init__(encoding=encoding, raw_bytes=raw_bytes, security=security)


    def hash(self, left, right=None):
        """
        Core hash utility

        Computes the digest of the provided arguments' concatenation in
        accordance with the machine's context. If only one argument is passed
        in, then the disgest of this single argument is computed

        :param left:  left member of the pair to be hashed
        :type left:   str or bytes
        :param right: [optional] right member of the pair to be hashed
        :type right:  bytes

        .. warning:: if ``right`` is provided, then ``left`` *must* also be of
                `bytes` type

        :returns: the digest of the entity occuring after concatenation of
                the given arguments
        :rtype: bytes
        """
        data = self.encode(left, right)
        hexdigest = self.algorithm(data).hexdigest()
        return bytes(hexdigest, self.encoding)


    def multi_hash(self, signed_hashes, start):
        """
        Extended hash utility

        Repeatedly applies the ``.hash()`` method over a tuple of signed digests
        parenthesized as specified by accompanying signs. Schematically speaking,
        the result of

        ``multi_hash(signed_hashes=((1, a), (1, b), (-1, c), (-1, d)), start=1)``

        equals ``hash(hash(a, hash(b, c)), d)``. If the provided sequence
        contains only one member, then this single digest is returned
        (without sign), that is,

                 ``multi_hash(signed_hashes=((+/-1, a)), start=1)``

        equals ``a`` (no hashing over single elements)

        .. warning:: When using this method, make sure that the combination of
                signs corresponds indeed to a valid parenthetization

        :param signed_hashes: a sequence of signed hashes
        :type signed_hashes: tuple of (+1/-1, bytes) pairs
        :param start: position where the application of ``.hash()`` will
                    start from
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
