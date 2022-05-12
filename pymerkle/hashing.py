"""
Provides the underlying hashing engine of Merkle-trees and verifiers.
"""

import hashlib
from pymerkle.exceptions import (UnsupportedHashType, UnsupportedEncoding,
                                 EmptyPathException, UndecodableArgumentError)


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


SUPPORTED_HASH_TYPES = ['md5', 'sha224', 'sha256', 'sha384', 'sha512',
                        'sha3_224', 'sha3_256', 'sha3_384', 'sha3_512', ]


class HashEngine:
    """
    Encapsulates the hashing functionality for Merkle-trees and verifiers.

    :param hash_type: [optional] Specifies the hash algorithm used by the
            engine. Defaults to *sha256*.
    :type hash_type: str
    :param encoding: [optional] Specifies the encoding algorithm used by the
            engine before hashing. Defaults to *utf_8*.
    :type encoding: str
    :param raw_bytes: [optional] Specifies whether the engine accepts raw
            binary data independently of its configured encoding type.
            Defaults to *True*.
    :type raw_bytes: bool
    :param security: [optional] Specifies whether defense against
            second-preimage attack will be enabled. Defaults to *True*.
    :type security: bool

    :raises UnsupportedHashType: if the provided encoding is not
                        contained in *SUPPORTED_ENCODINGS*.
    :raises UnsupportedHashType: if the provided hash-type is not
                        contained in *SUPPORTED_HASH_TYPES*.
    """

    def __init__(self, hash_type='sha256', encoding='utf-8',
                 raw_bytes=True, security=True):

        _hash_type = hash_type.lower().replace('-', '_')
        if _hash_type not in SUPPORTED_HASH_TYPES:
            raise UnsupportedHashType('Hash type %s is not supported'
                                      % _hash_type)

        _encoding = encoding.lower().replace('-', '_')
        if _encoding not in SUPPORTED_ENCODINGS:
            raise UnsupportedEncoding('Encoding type %s is not supported'
                                      % _encoding)

        self.hash_type = _hash_type
        self.algorithm = getattr(hashlib, self.hash_type)
        self.encoding = _encoding
        self.raw_bytes = raw_bytes
        self.security = security

        self.concatenate = self._mk_encode_func()

    def _mk_encode_func(self):
        """
        Constructs the encoding functionality of the present engine in
        accordance with its initial configuration.
        """
        # Resolve security prefices
        if self.security:
            prefix_0_dec = '\x00'
            prefix_1_dec = '\x01'
            prefix_0_enc = bytes('\x00', self.encoding)
            prefix_1_enc = bytes('\x01', self.encoding)
        else:
            prefix_0_dec = ''
            prefix_1_dec = ''
            prefix_0_enc = bytes()
            prefix_1_enc = bytes()

        # Make encoding funtion
        if self.raw_bytes:
            def encode_func(left, right=None):
                if not right:
                    if isinstance(left, bytes):
                        data = prefix_0_enc + left
                    else:
                        data = prefix_0_enc + bytes(left, self.encoding)
                else:
                    data = prefix_1_enc + left + prefix_1_enc + right
                return data
        else:
            def encode_func(left, right=None):
                if not right:
                    if isinstance(left, bytes):
                        try:
                            left = left.decode(self.encoding)
                        except UnicodeDecodeError:
                            raise UndecodableArgumentError
                        data = bytes(prefix_0_dec + left, self.encoding)
                    else:
                        data = bytes(prefix_0_dec + left, self.encoding)
                else:
                    try:
                        left = left.decode(self.encoding)
                        right = right.decode(self.encoding)
                    except UnicodeDecodeError:
                        raise UndecodableArgumentError
                    data = bytes(prefix_1_dec + left + prefix_1_dec + right,
                                 self.encoding)
                return data

        return encode_func

    def hash(self, left, right=None):
        """
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
        bytestring = self.concatenate(left, right)
        checksum = self.algorithm(bytestring).hexdigest()

        return checksum.encode(self.encoding)

    def multi_hash(self, path, offset):
        """
        Repeatedly applies the *hash()* method over the provided iterable of
        signed hashes, where signs indicate parenthetization and *offset* is
        the starting position. Schematically speaking,

        ``multi_hash([(1, a), (1, b), (-1, c), (-1, d)], 1)``

        is equivalent to

        ``hash(hash(a, hash(b, c)), d)``.

        .. note:: If the provided iterable contains only one element, then this
            single hash is returned (without sign), that is,

                 ``multi_hash(((+/-1, a)), 0)``

            equals ``a`` (no hashing over single elements)

        .. warning:: When using this method, make sure that the combination of
                signs corresponds indeed to a valid parenthetization.

        :param path: sequence of signed hashes
        :type path: iterable of (+1/-1, bytes)
        :param offset: starting position for hashing
        :type offset: int
        :rtype: bytes

        :raises EmptyPathException: if the provided sequence was empty
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

                checksum = self.hash(path[i][1], path[i + 1][1])
                move = +1

            else:

                # Pair with left neighbour
                sign = path[i - 1][0]

                checksum = self.hash(path[i - 1][1], path[i][1])
                move = -1

            path[i] = (sign, checksum)

            # Shrink
            del path[i + move]
            if move < 0:
                i -= 1

        return path[0][1]
