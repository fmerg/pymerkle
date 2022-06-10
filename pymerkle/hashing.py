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


SUPPORTED_ALGORITHMS = ['md5', 'sha224', 'sha256', 'sha384', 'sha512',
                        'sha3_224', 'sha3_256', 'sha3_384', 'sha3_512', ]


class UnsupportedParameter(Exception):
    """
    Raised when a hashing engine with unsupported parameters is requested.
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

    :param algorithm: [optional] Specifies the hash algorithm used by the
        engine. Defaults to *sha256*.
    :type algorithm: str
    :param encoding: [optional] Specifies the encoding algorithm used by the
        engine before hashing. Defaults to *utf_8*.
    :type encoding: str
    :param security: [optional] Specifies whether defense against
        second-preimage attack will be enabled. Defaults to *True*.
    :type security: bool

    :raises UnsupportedParameter: if the provided hash-type or encoding is not
        included in ``SUPPORTED_ALGORITHMS`` or ``SUPPORTED_ENCODINGS``
        respectively.
    """

    def __init__(self, algorithm='sha256', encoding='utf-8', security=True):

        for (attr, provided, supported) in (
                ('algorithm', algorithm, SUPPORTED_ALGORITHMS),
                ('encoding', encoding, SUPPORTED_ENCODINGS)):

            _provided = provided.lower().replace('-', '_')

            if _provided not in supported:
                raise UnsupportedParameter(f'{provided} is not supported')

            setattr(self, attr, _provided)

        self.security = security

        if security:
            self.prefx00 = '\x00'.encode(encoding)
            self.prefx01 = '\x01'.encode(encoding)
        else:
            self.prefx00 = bytes()
            self.prefx01 = bytes()

    def _hash(self, buff):
        """
        Returns the hexdigest of the provided data under the engine's
        configured hash algorithm.

        :param buff: data to hash
        :type buff: bytes
        :rtype: bytes
        """
        hasher = getattr(hashlib, self.algorithm)()
        update = hasher.update

        offset = 0
        chunksize = 1024
        chunk = buff[offset: chunksize]
        while chunk:
            update(chunk)
            offset += chunksize
            chunk = buff[offset: offset + chunksize]

        return hasher.hexdigest().encode(self.encoding)

    def hash_record(self, data):
        """
        Computes the digest of the provided record under the engine's configured
        hash algorithm, after first appending the ``\\x00`` security prefix.
        """
        buff = self.prefx00 + (data if isinstance(data, bytes) else
                               data.encode(self.encoding))

        return self._hash(buff)

    def hash_pair(self, left, right):
        """
        Concatenates the provided bytestrings after first appending the
        ``\\x01`` security prefix and computes the digest under the engine's
        configured hash algorithm.

        :param left: left sequence
        :type left: bytes
        :param right: right sequence
        :type right: bytes
        :rtype: bytes
        """
        buff = self.prefx01 + left + self.prefx01 + right

        return self._hash(buff)

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
                if i == 0:
                    sign = +1
                else:
                    sign = path[i + 1][0]
                digest = self.hash_pair(path[i][1], path[i + 1][1])
                move = +1
            else:
                # Pair with left neighbour
                sign = path[i - 1][0]
                digest = self.hash_pair(path[i - 1][1], path[i][1])
                move = -1

            path[i] = (sign, digest)

            # Shrink
            del path[i + move]
            if move < 0:
                i -= 1

        return path[0][1]
