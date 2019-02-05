"""
Contains a class ``hash_machine`` encapsulating the two basic hash utilities used accross the library.
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
    'sha512']
"""Supported hash types. If SHA3 is supported locally, then the above list will include also
*sha3_224*, *sha3_256*, *sha3_384*, *sha3_512*"""

try:  # to extend hash types if SHA3 is supported
    import sha3
except BaseException:
    pass
else:
    HASH_TYPES.extend(['sha3_224', 'sha3_256', 'sha3_384', 'sha3_512'])


class hash_machine(object):
    """Encapsulates the two basic hash utilities used accross this library.

    Sole purpose of this class is to fix at construction the hash and encoding types used for encryption,
    so that these parameters need not be redefined every time a hash utility is invoked. Instances
    of this class are thus to be initialized with every new construction of a Merkle-Tree or every time
    a proof validation is about to be performed

    :param hash_type: specifies the hash algorithm to be used by the machine; must be among the elements of the ``HASH_TYPES``
                      global variable (upper- or mixed-case with '-' instead of '_' allowed). Defaults to ``sha256``
                      if unspecified
    :type hash_type:  str
    :param encoding:  specifies the encoding algorithm to be used by machine before hashing; must be among the elements of the
                      ENCODINGS global variable (upper- or mixed-case with ``-`` instead of ``_`` allowed). Defaults to ``utf_8``
                      if unspecified
    :type encoding:   str
    :param security:  defaults to ``True``; plays role only if hash and encoding types are sha256 and utf-8 respectively. In this
                      case, security standards are applied against second-preimage attack, i.e., single, resp. double arguments of
                      the ``hash()`` function will be prepended with ``'x00'``, resp. ``'x01'`` before hashing
    :type security:   bool

    :raises Exception: if ``hash_type``, resp. ``encoding`` is not contained in ``HASH_TYPES``, resp. ``ENCODINGS``

    :ivar HASH_ALGORITHM: (*builtin_function_or_method*) Hash algorithm used by the machine. Defaults to SHA256.
    :ivar ENCODING:       (*str*) Encoding type used by the machine while hashing. Defaults to UTF-8.
    :ivar SECURITY:       (*bool*) Indicates that defense against second-preimage attack is activated (genuinely only for
                          default values of hash and encoding types). Defaults to ``True``.
    """

    # -------------------------------- Construction --------------------------

    def __init__(self, hash_type='sha256', encoding='utf-8', security=True):

        # Hash algorithm used by the machine
        self.HASH_ALGORITHM = hash_machine.select_hash_algorithm(
            hash_type=hash_type.lower().replace('-', '_'))

        # Encoding type used by this machine before hashing
        self.ENCODING = hash_machine.select_encoding(
            encoding=encoding.lower().replace('-', '_'))

        # Plays role only if hash and endodin types is SHA256, resp. UTF-8
        self.SECURITY = security
        if self.SECURITY and self.HASH_ALGORITHM == hashlib.sha256 and self.ENCODING == 'utf_8':
            # ~ Security prefices will be prepended before hashing for defense against
            self.PREFIX_0, self.PREFIX_1 = '\x00', '\x01'

    @staticmethod
    def select_hash_algorithm(hash_type):
        """Extracts from the ``hashlib`` module the desired hash algorithm according to the inserted label

        :param hash_type: label indicating the desired hash algorithm
        :type hash_type:  str
        :returns:         the desired hash algorithm; e.g. ``hashlib.sha256``
        :rtype:           ``builtin_function_or_method``

        :raises Exception: if ``hash_type`` is not contained in ``HASH_TYPES``
        """
        if hash_type in HASH_TYPES:
            return getattr(hashlib, hash_type)
        else:
            message = '\n\n * Hash type {hash_type} is not supported'.format(
                hash_type=hash_type)
            if hash_type[:4] == 'sha3':
                message += '. Run the command\
                   \n\
                   \n   pip install pysha3==1.0b1\
                   \n\
                   \n   to install `sha3` depending on https://pypi.python.org/pypi/pysha3\n'
            else:
                message += '\n'
            raise Exception(message)

    @staticmethod
    def select_encoding(encoding):
        """Sole purpose of this function is to throw an exception if the inserted encoding type is not supported

        :param encoding: label indicating the desired encoding type
        :type encoding:  str
        :returns:        just the inserted argument
        :rtype:          ``str``

        :raises Exception: if ``encoding`` is not contained in ``ENCODINGS``
        """
        if encoding in ENCODINGS:
            return encoding
        else:
            raise Exception(
                '\n\n * Encoding type {encoding} is not supported\n'.format(encoding=encoding))

    def security_mode_activated(self):
        """
        :returns: ``True`` iff genuine security standards are activated (i.e., ``self.SECURITY`` is ``True``
                  along with hash, resp. ecoding type of the machine being ``SHA256``, resp. ``UTF-8``)
        :rtype:   ``bool``
        """
        return self.SECURITY and self.HASH_ALGORITHM == hashlib.sha256 and self.ENCODING == 'utf_8'

    # ------------------------------- Hash utils -----------------------------

    def hash(self, first, second=None):
        """Core hash utility

        Returns in hexadecimal form the hash of the object occuring by concatenation of arguments in the given
        order; if only one argument is passed in, then the hash of this single argument is returned

        :param first:  left member of the pair to be hashed
        :type first:   str or bytes or bytearray
        :param second: [optional] right member of the pair to be hashed; if provided, then ``first`` must also
                       be of ``str`` type (valid hex)
        :type second:  str
        :returns:      a valid hex representing the produced hash
        :rtype:        ``str``
        """

        if not second:  # one arg case

            if isinstance(first, (bytes, bytearray)):
                # bytes-like input

                if self.security_mode_activated():
                    # Apply security stadards
                    return self.HASH_ALGORITHM(
                        bytes(
                            self.PREFIX_0,
                            encoding=self.ENCODING) +
                        first).hexdigest()

                # No security standards
                return self.HASH_ALGORITHM(first).hexdigest()

            # Non bytes-like input

            if self.security_mode_activated():

                # Apply security standards
                return self.HASH_ALGORITHM(
                    bytes(
                        '{}{}'.format(
                            self.PREFIX_0,
                            first),
                        encoding=self.ENCODING)).hexdigest()

            # No security standards
            return self.HASH_ALGORITHM(
                bytes(first, encoding=self.ENCODING)).hexdigest()

        # two args case

        if self.security_mode_activated():

            # Apply security standards
            return self.HASH_ALGORITHM(
                bytes(
                    '{}{}{}{}'.format(
                        self.PREFIX_1,
                        first,
                        self.PREFIX_1,
                        second),
                    encoding=self.ENCODING)).hexdigest()

        # No security standards
        return self.HASH_ALGORITHM(
            bytes(
                '{}{}'.format(
                    first,
                    second),
                encoding=self.ENCODING)).hexdigest()

    def multi_hash(self, signed_hashes, start):
        """Hash utility used in proof validation

        Repeatedly applies the core ``hash()`` method over a tuple of signed hashes parenthesized in pairs
        as specified by accompanying signs

        :param signed_hashes: a sequence of signed hashes
        :type signed_hashes:  tuple of (+1/-1, hash) pairs, where hash is of type ``str`` or ``bytes`` or ``bytearray``
        :param start:         position where the application of ``hash()`` will start from
        :type start:          int
        :returns:             a valid hexadecimal representing the computed hash
        :rtype:               ``str``

        :Example:

        >>> from pymerkle.hashing import hash_machine
        >>> machine = hash_machine()
        >>> machine.multi_hash(((1, 'a'), (1, 'b'), (-1, 'c'), (-1, 'd')), 1)
        '1453fd7ac377d0892731cfdbd60f656db6ed0d4f4475657335945634bb6d3243'

        the result being equivalent to

        ``hash(hash('a', hash('b', 'c')), 'd')``

        .. note:: Returns ``None`` if the inserted sequence of signed hashes was empty
        .. warning:: When using this method, make sure that the combination of signs corresponds indeed
                     to a valid parenthetization
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
            # `signed_hashes` contained one element
            return self.hash(signed_hashes[0][1])
        # `signed_hashes` was equal to []
        return None
