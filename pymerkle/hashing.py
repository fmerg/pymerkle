"""
Provides the underlying hashing machinery for encryption and proof
verification.
"""

import hashlib


SUPPORTED_ENCODINGS = ['ascii', 'big5', 'big5hkscs', 'cp037', 'cp1026', 'cp1125',
                       'cp1140', 'cp1250', 'cp1251', 'cp1252', 'cp1253', 'cp1254', 'cp1255',
                       'cp1256', 'cp1257', 'cp1258', 'cp273', 'cp424', 'cp437', 'cp500', 'cp775',
                       'cp850', 'cp852', 'cp855', 'cp857', 'cp858', 'cp860', 'cp861', 'cp862',
                       'cp863', 'cp864', 'cp865', 'cp866', 'cp869', 'cp932', 'cp949', 'cp950',
                       'euc_jis_2004', 'euc_jisx0213', 'euc_jp', 'euc_kr', 'gb18030', 'gb2312',
                       'gbk', 'hp_roman8', 'hz', 'iso2022_jp', 'iso2022_jp_1', 'iso2022_jp_2',
                       'iso2022_jp_2004', 'iso2022_jp_3', 'iso2022_jp_ext', 'iso2022_kr',
                       'iso8859_10', 'iso8859_11', 'iso8859_13', 'iso8859_14', 'iso8859_15',
                       'iso8859_16', 'iso8859_2', 'iso8859_3', 'iso8859_4', 'iso8859_5',
                       'iso8859_6', 'iso8859_7', 'iso8859_8', 'iso8859_9', 'johab', 'koi8_r',
                       'koi8_u', 'kz1048', 'latin_1', 'mac_cyrillic', 'mac_greek', 'mac_iceland',
                       'mac_latin2', 'mac_roman', 'mac_turkish', 'ptcp154', 'shift_jis',
                       'shift_jis_2004', 'shift_jisx0213', 'tis_620', 'utf_16', 'utf_16_be',
                       'utf_16_le', 'utf_32', 'utf_32_be', 'utf_32_le', 'utf_7', 'utf_8', ]
"""List of supported hash types"""


SUPPORTED_HASH_TYPES = ['md5', 'sha224', 'sha256', 'sha384', 'sha512',
                        'sha3_224', 'sha3_256', 'sha3_384', 'sha3_512', ]
"""List of supported encoding types"""


class UnsupportedParameter(Exception):
    """
    Raised when a hashing engine with unsupported paramter is requested.
    """
    pass


class EmptyPathException(Exception):
    """
    Raised when an empty path of hashes is fed to a hashing engine.
    """
    pass


class HashEngine:
    """
    Encapsulates the hashing functionality of Merkle-trees and proof
    verification.

    :param hash_type: [optional] Specifies the hash algorithm used by the
        engine. Defaults to *sha256*.
    :type hash_type: str
    :param encoding: [optional] Specifies the encoding algorithm used by the
        engine before hashing. Defaults to *utf_8*.
    :type encoding: str
    :param security: [optional] Specifies whether defense against
        second-preimage attack will be enabled. Defaults to *True*.
    :type security: bool

    :raises UnsupportedParameter: if the provided hash-type or encoding is not
        included in ``SUPPORTED_HASH_TYPES`` or ``SUPPORTED_ENCODINGS``
        respectively.
    """

    def __init__(self, hash_type='sha256', encoding='utf-8', security=True):

        _hash_type = hash_type.lower().replace('-', '_')
        if _hash_type not in SUPPORTED_HASH_TYPES:
            raise UnsupportedParameter(f'{hash_type} is not supported')

        _encoding = encoding.lower().replace('-', '_')
        if _encoding not in SUPPORTED_ENCODINGS:
            raise UnsupportedParameter(f'{encoding} is not supported')

        self.hash_type = _hash_type
        self.algorithm = getattr(hashlib, self.hash_type)
        self.encoding = _encoding
        self.security = security

        if self.security:
            self.prefix_0 = '\x00'.encode(self.encoding)
            self.prefix_1 = '\x01'.encode(self.encoding)
        else:
            self.prefix_0 = bytes()
            self.prefix_1 = bytes()

    def concatenate(self, left, right=None):
        """
        Computes the concatenation of the provided byte strings.

        If in security mode (as is default), the provided sequences are
        prepended with ``0x01`` under the engine's encoding type. If the
        secondf argument is omitted, then the provided one is prepended with
        ``0x01``.

        :param left: left sequence
        :type left: bytes
        :param right: [optional] right sequence
        :type right: bytes
        :returns: Concatenation of the provided sequences as determined by the
           encoding and security mode of the present engine.
        :rtype: bytes
        """
        if right is None:

            if isinstance(left, bytes):
                return self.prefix_0 + left

            return self.prefix_0 + left.encode(self.encoding)

        return self.prefix_1 + left + self.prefix_1 + right


    def hash(self, left, right=None):
        """
        Computes the digest of the concatenation of the probided byte strings
        using the engine's configured hash algorithm. If *right* is omitted,
        then the digest of *left* (prepended with ``0x00``) is computed.

        .. note:: The exact nature of the concatenation is determined by the
            encoding type and security mode of the engine (cf. the
            *concatenate()* method).

        :param left: left sequence
        :type left: bytes
        :param right: [optional] right sequence
        :type right: bytes

        :returns: Digest of the conatenation of the provided byte strings.
        :rtype: bytes
        """
        bytestring = self.concatenate(left, right)
        checksum = self.algorithm(bytestring).hexdigest()
        digest = checksum.encode(self.encoding)

        return digest

    def multi_hash(self, path, offset):
        """
        Computes the checksum which occurs after repetedly applying *hash()*
        over the provided *path* of hashes, were signs indicate
        parenthetization in terms of pairing and *offset* is the starting
        position counting from zero. Schematically speaking,

        ``multi_hash([(1, a), (1, b), (-1, c), (-1, d)], 1)``

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

        .. note:: If the provided path of hashes contains only one element,
            then this single hash is returned without sign; schematically
            speaking,

                 ``multi_hash(((+/-1, a)), 0) = a``

            (no hashing of single elements).
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

                if i == 0:
                    sign = +1
                else:
                    sign = path[i + 1][0]
                digest = self.hash(path[i][1], path[i + 1][1])
                move = +1

            else:
                # Pair with left neighbour

                sign = path[i - 1][0]
                digest = self.hash(path[i - 1][1], path[i][1])
                move = -1

            path[i] = (sign, digest)

            # Shrink
            del path[i + move]
            if move < 0:
                i -= 1

        return path[0][1]
