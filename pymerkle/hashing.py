"""Provides a class ``hash_machine`` encapsulating the hash utilities used accross the library. Instances of this class
should receive their configuration parameters from the ``ENCODINGS`` and ``HASH_TYPES`` global variables of this module
"""

import hashlib
from pymerkle.exceptions import NotSupportedEncodingError, NotSupportedHashTypeError, EmptyPathException, UndecodableArgumentError

ENCODINGS = [
    'ascii',
    'big5',
    'big5hkscs',
    'cp037',
    'cp1026',
    'cp1125',
    'cp1140',
    'cp1250',
    'cp1251',
    'cp1252',
    'cp1253',
    'cp1254',
    'cp1255',
    'cp1256',
    'cp1257',
    'cp1258',
    'cp273',
    'cp424',
    'cp437',
    'cp500',
    'cp775',
    'cp850',
    'cp852',
    'cp855',
    'cp857',
    'cp858',
    'cp860',
    'cp861',
    'cp862',
    'cp863',
    'cp864',
    'cp865',
    'cp866',
    'cp869',
    'cp932',
    'cp949',
    'cp950',
    'euc_jis_2004',
    'euc_jisx0213',
    'euc_jp',
    'euc_kr',
    'gb18030',
    'gb2312',
    'gbk',
    'hp_roman8',
    'hz',
    'iso2022_jp',
    'iso2022_jp_1',
    'iso2022_jp_2',
    'iso2022_jp_2004',
    'iso2022_jp_3',
    'iso2022_jp_ext',
    'iso2022_kr',
    'iso8859_10',
    'iso8859_11',
    'iso8859_13',
    'iso8859_14',
    'iso8859_15',
    'iso8859_16',
    'iso8859_2',
    'iso8859_3',
    'iso8859_4',
    'iso8859_5',
    'iso8859_6',
    'iso8859_7',
    'iso8859_8',
    'iso8859_9',
    'johab',
    'koi8_r',
    'kz1048',
    'latin_1',
    'mac_cyrillic',
    'mac_greek',
    'mac_iceland',
    'mac_latin2',
    'mac_roman',
    'mac_turkish',
    'ptcp154',
    'shift_jis',
    'shift_jis_2004',
    'shift_jisx0213',
    'tis_620',
    'utf_16',
    'utf_16_be',
    'utf_16_le',
    'utf_32',
    'utf_32_be',
    'utf_32_le',
    'utf_7',
    'utf_8'
]
"""Supported encoding types"""

HASH_TYPES = [
    'md5',
    'sha224',
    'sha256',
    'sha384',
    'sha512',
    'sha3_224',
    'sha3_256',
    'sha3_384',
    'sha3_512'
]
"""Supported hash types"""


class hash_machine(object):
    """Encapsulates the basic hash utilities used accross this library.

    Sole purpose of this class is to fix at construction the hash and encoding types used for encryption, so that these parameters
    need not be redefined every time a hash utility is invoked. Instances of this class are thus to be initialized with every new
    construction of a Merkle-tree or every time a proof validation is about to be performed

    :param hash_type: Defaults to ``'sha256'``. Specifies the hash algorithm to be used by the machine. Must must be among the
                      elements of ``HASH_TYPES`` (upper- or mixed-case with '-' instead of '_' allowed).
    :type hash_type:  str
    :param encoding:  Defaults to ``'utf_8'``. Specifies the encoding algorithm to be used by the machine before hashing. Must be
                      among the elements of ``ENCODINGS`` (upper- or mixed-case with ``-`` instead of ``_`` allowed).
    :type encoding:   str
    :param security:  Defaults to ``True``. Specifies whether the machine applies security standards against second-preimage
                      attack (i.e., whether single, resp. double arguments passed into the ``.hash`` method will be prepended
                      with ``'0x00'``, resp. ``'0x01'`` before hashing)
    :type security:   bool

    :raises NotSupportedHashTypeError: if ``hash_type`` is not contained in ``HASH_TYPES``
    :raises NotSupportedEncodingType : if ``encoding`` is not contained in ``ENCODINGS``

    :ivar HASH_ALGORITHM: (*builtin_function_or_method*) Hash algorithm used by the machine
    :ivar ENCODING:       (*str*) Encoding type used by the machine before hashing
    :ivar SECURITY:       (*bool*) Indicates whether defense against second-preimage attack is activated
    :self.PREFIX_0:       (*str*) ``'\x00'`` if defense against second-preimage attack is activated, else ``''``
    :self.PREFIX_1:       (*str*) ``'\x01'`` if defense against second-preimage attack is activated, else ``''``
    """

    def __init__(self, hash_type='sha256', encoding='utf-8', security=True):

        # Select hash-algorithm

        _hash_type = hash_type.lower().replace('-', '_')

        if _hash_type not in HASH_TYPES:
            raise NotSupportedHashTypeError('Hash type %s is not supported' % hash_type)

        self.HASH_ALGORITHM = getattr(hashlib, _hash_type)

        # Select encoding

        _encoding = encoding.lower().replace('-', '_')

        if _encoding not in ENCODINGS:
            raise NotSupportedEncodingError('Encoding type %s is not supported' % encoding)

        self.ENCODING = _encoding

        # ~ If True, security prefices will be prepended before
        # ~ hashing for defense against second-preimage attack

        self.SECURITY = security
        self.PREFIX_0 = '\x00' if security else ''
        self.PREFIX_1 = '\x01' if security else ''


    def hash(self, left, right=None):
        """Core hash utility

        Returns the digest of given arguments' concatenation. If only one argument
        is passed in, then the disgest of this single argument is returned

        :param left:  left member of the pair to be hashed
        :type left:   str or bytes or bytearray
        :param right: [optional] right member of the pair to be hashed
        :type right:  bytes or bytearray

        .. warning:: if ``right`` is provided, then ``left`` *must* also be of `bytes` or `byetarray` type

        :returns:      the digest of the entity occuring after concatenation of the given arguments
        :rtype:        bytes
        """

        if not right:                                                           # single argument case

            if isinstance(left, (bytes, bytearray)):                            # bytes-like input

                try:
                    _hexdigest = self.HASH_ALGORITHM(
                            bytes(
                                '%s%s' % (
                                    self.PREFIX_0,
                                    left.decode(self.ENCODING)
                                ),
                                self.ENCODING
                            )
                        ).hexdigest()

                except UnicodeDecodeError:                                      # incompatible encoding type
                    raise UndecodableArgumentError

                return bytes(_hexdigest, self.ENCODING)

            else:                                                               # string input

                _hexdigest = self.HASH_ALGORITHM(
                        bytes(
                            '%s%s' % (
                                self.PREFIX_0,
                                left
                            ),
                            self.ENCODING
                        )
                    ).hexdigest()

                return bytes(_hexdigest, self.ENCODING)

        else:                                                                   # two arguments case

            try:
                _hexdigest = self.HASH_ALGORITHM(
                        bytes(
                            '%s%s%s%s' % (
                                self.PREFIX_1,
                                left.decode(self.ENCODING),
                                self.PREFIX_1,
                                right.decode(self.ENCODING)
                            ),
                            self.ENCODING
                        )
                    ).hexdigest()

            except UnicodeDecodeError:                                          # incompatible encoding type
                raise UndecodableArgumentError

            return bytes(_hexdigest, self.ENCODING)


    def multi_hash(self, signed_hashes, start):
        """Extended hash utility used in proof validation

        Repeatedly applies the ``.hash()`` method over a tuple of signed digests parenthesized as specified
        by accompanying signs. Schematically speaking, the result of

            ``multi_hash(signed_hashes=((1, a), (1, b), (-1, c), (-1, d)), start=1)``

        equals ``hash(hash(a, hash(b, c)), d)``. If the provided sequence contains only one member, then this
        one hash is returned (without sign). That is,

            ``multi_hash(signed_hashes=((+/-1, a)), start=1)``

        equals ``a`` (no hashing over single elements)

        .. warning:: When using this method, make sure that the combination of signs corresponds to a valid parenthetization

        :param signed_hashes: a sequence of signed hashes
        :type signed_hashes:  tuple of (+1/-1, bytes) pairs
        :param start:         position where the application of ``.hash()`` will start from
        :type start:          int
        :returns:             the computed digest
        :rtype:               bytes

        :raises EmptyPathException: if the provided sequence was empty
        """

        signed_hashes = list(signed_hashes)

        if signed_hashes == []:                                                 # Empty-tuple case
            raise EmptyPathException

        elif len(signed_hashes) == 1:                                           # One-element case
            return signed_hashes[0][1]

        else:

            i = start
            while len(signed_hashes) > 1:

                if signed_hashes[i][0] == +1:                                   # Pair with the right neighbour

                    if i == 0:

                        new_sign = +1
                    else:
                        new_sign = signed_hashes[i + 1][0]

                    new_hash = self.hash(
                        signed_hashes[i][1],
                        signed_hashes[i + 1][1]
                    )
                    move = +1

                else:                                                           # Pair with the left neighbour
                    new_sign = signed_hashes[i - 1][0]

                    new_hash = self.hash(
                        signed_hashes[i - 1][1],
                        signed_hashes[i][1]
                    )
                    move = -1

                # Store and shrink

                signed_hashes[i] = (new_sign, new_hash)
                del signed_hashes[i + move]

                if move < 0:
                    i -= 1

            # Return the unique element having remained after shrinking

            return signed_hashes[0][1]
