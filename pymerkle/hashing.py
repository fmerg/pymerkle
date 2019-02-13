"""
Provides a class ``hash_machine`` encapsulating the two basic hash utilities used accross the library.
Instances of this class should receive their configuration parameters from the ``ENCODINGS`` and
``HASH_TYPES`` global variables of this module
"""

import pymerkle.encodings  # Load encoding types
import hashlib

ENCODINGS = pymerkle.encodings.ENCODINGS
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
    """Encapsulates the two basic hash utilities used accross this library.

    Sole purpose of this class is to fix at construction the hash and encoding types used for encryption,
    so that these parameters need not be redefined every time a hash utility is invoked. Instances
    of this class are thus to be initialized with every new construction of a Merkle-tree or every time
    a proof validation is about to be performed

    :param hash_type: specifies the hash algorithm to be used by the machine; must be among the elements of the ``HASH_TYPES``
                      global variable (upper- or mixed-case with '-' instead of '_' allowed). Defaults to ``'sha256'``
                      if unspecified
    :type hash_type:  str
    :param encoding:  specifies the encoding algorithm to be used by machine before hashing; must be among the elements of the
                      ENCODINGS global variable (upper- or mixed-case with ``-`` instead of ``_`` allowed). Defaults to ``'utf_8'``
                      if unspecified
    :type encoding:   str
    :param security:  defaults to ``True``, in which case security standards are applied against second-preimage attack, i.e.,
                      single, resp. double arguments of the ``.hash`` method will be prepended with ``'\\x00'``, resp. ``'\\x01'``
                      before hashing
    :type security:   bool

    :raises Exception: if ``hash_type``, resp. ``encoding`` is not contained in ``hashing.HASH_TYPES``, resp. ``hashing.ENCODINGS``

    :ivar HASH_ALGORITHM: (*builtin_function_or_method*) Hash algorithm used by the machine, specified in the obvious way
                          by the ``hash_type`` argument at construction
    :ivar ENCODING:       (*str*) Encoding type used by the machine before hashing, specified in the obvious way
                          by the ``encoding`` argument at construction
    :ivar SECURITY:       (*bool*) Indicates whether defense against second-preimage attack is activated, specified in the
                          obvious way by the ``security`` argument at construction
    """

    # -------------------------------- Construction --------------------------

    def __init__(self, hash_type='sha256', encoding='utf-8', security=True):

        # Hash algorithm used by the machine
        self.HASH_ALGORITHM = hash_machine.select_hash_algorithm(
            hash_type=hash_type.lower().replace('-', '_'))

        # Encoding type used by this machine before hashing
        self.ENCODING = hash_machine.select_encoding(
            encoding=encoding.lower().replace('-', '_'))

        self.SECURITY = security
        if self.SECURITY:
            # Prefices will be prepended before hashing for defense against
            # second-preimage attack
            self.PREFIX_0, self.PREFIX_1 = '\x00', '\x01'

    @staticmethod
    def select_hash_algorithm(hash_type):
        """Extracts from the ``hashlib`` module the desired hash algorithm according to the inserted label

        :param hash_type: label indicating the desired hash algorithm
        :type hash_type:  str
        :returns:         the desired hash algorithm; e.g. ``hashlib.sha256``
        :rtype:           builtin_function_or_method

        :raises Exception: if ``hash_type`` is not contained in ``hashing.HASH_TYPES``
        """
        if hash_type in HASH_TYPES:
            return getattr(hashlib, hash_type)
        else:
            message = f'\n\n * Hash type {hash_type} is not supported\n'
            raise Exception(message)

    @staticmethod
    def select_encoding(encoding):
        """Sole purpose of this function is to throw an exception if the inserted encoding type is not supported

        :param encoding: label indicating the desired encoding type
        :type encoding:  str
        :returns:        just the inserted argument
        :rtype:          str

        :raises Exception: if ``encoding`` is not contained in ``hashing.ENCODINGS``
        """
        if encoding in ENCODINGS:
            return encoding
        else:
            raise Exception(
                '\n\n * Encoding type {encoding} is not supported\n'.format(encoding=encoding))

    # ------------------------------- Hash utils -----------------------------

    def hash(self, first, second=None):
        """Core hash utility

        Returns the hash of the object occuring by concatenation of arguments in the given order.
        If only one argument is passed in, then the hash of this single argument is returned

        :param first:  left member of the pair to be hashed
        :type first:   str or bytes or bytearray
        :param second: [optional] right member of the pair to be hashed
        :type second:  bytes or bytearray

        .. warning:: if ``second`` is provided, then ``first`` *must* also be of `bytes`
                    or `byetarray` type

        :returns:      the hash of the provided pair
        :rtype:        bytes
        """

        if not second:  # one arg case

            if isinstance(first, (bytes, bytearray)):
                # bytes-like input

                if self.SECURITY:
                    # Apply security stadards
                    hex_hash = self.HASH_ALGORITHM(
                        bytes(
                            self.PREFIX_0,
                            encoding=self.ENCODING) +
                        first).hexdigest()
                    return bytes(hex_hash, encoding=self.ENCODING)

                # No security standards
                hex_hash = self.HASH_ALGORITHM(first).hexdigest()
                return bytes(hex_hash, encoding=self.ENCODING)

            # Non bytes-like input

            if self.SECURITY:

                # Apply security standards
                hex_hash = self.HASH_ALGORITHM(
                    bytes(
                        '{}{}'.format(
                            self.PREFIX_0,
                            first),
                        encoding=self.ENCODING)).hexdigest()
                return bytes(hex_hash, encoding=self.ENCODING)

            # No security standards
            hex_hash = self.HASH_ALGORITHM(
                bytes(first, encoding=self.ENCODING)).hexdigest()
            return bytes(hex_hash, encoding=self.ENCODING)

        # two args case

        if self.SECURITY:

            # Apply security standards
            hex_hash = self.HASH_ALGORITHM(
                bytes(
                    '{}{}{}{}'.format(
                        self.PREFIX_1,
                        first.decode(encoding=self.ENCODING),
                        self.PREFIX_1,
                        second.decode(encoding=self.ENCODING)),
                    encoding=self.ENCODING)).hexdigest()
            return bytes(hex_hash, encoding=self.ENCODING)

        # No security standards
        hex_hash = self.HASH_ALGORITHM(
            bytes(
                '{}{}'.format(
                    first.decode(encoding=self.ENCODING),
                    second.decode(encoding=self.ENCODING)),
                encoding=self.ENCODING)).hexdigest()
        return bytes(hex_hash, encoding=self.ENCODING)

    def multi_hash(self, signed_hashes, start):
        """Hash utility used in proof validation

        Repeatedly applies the ``.hash`` method over a tuple of signed hashes parenthesized in pairs
        as specified by accompanying signs. Schematically speaking, the result of

            ``multi_hash(signed_hashes=((1, a), (1, b), (-1, c), (-1, d)), start=1)``

        is equivalent to ``hash(hash(a, hash(b, c)), d)``.

        .. warning:: When using this method, make sure that the combination of signs corresponds indeed
                     to a valid parenthetization

        :param signed_hashes: a sequence of signed hashes
        :type signed_hashes:  tuple of (+1/-1, bytes) pairs
        :param start:         position where the application of ``.hash`` will start from
        :type start:          int
        :returns:             the computed hash
        :rtype:               bytes

        .. note:: Returns ``None`` if the inserted sequence of signed hashes was empty
        """

        signed_hashes = list(signed_hashes)

        # Calculate and return
        if signed_hashes != []:
            if len(signed_hashes) > 1:
                i = start
                while len(signed_hashes) > 1:
                    if signed_hashes[i][0] == +1:
                        # Pair with the right neighbour
                        if i == 0:
                            new_sign = +1
                        else:
                            new_sign = signed_hashes[i + 1][0]
                        new_hash = self.hash(
                            signed_hashes[i][1], signed_hashes[i + 1][1])
                        move = +1
                    else:
                        # Pair with the left neighbour
                        new_sign = signed_hashes[i - 1][0]
                        new_hash = self.hash(
                            signed_hashes[i - 1][1], signed_hashes[i][1])
                        move = -1
                    # Store and shrink
                    signed_hashes[i] = (new_sign, new_hash)
                    del signed_hashes[i + move]
                    if move < 0:
                        i -= 1
                return signed_hashes[0][1]
            # signed_hashes contained one element
            return self.hash(signed_hashes[0][1])
        # signed_hashes was empty
        return None
