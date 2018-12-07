from .encodings import ENCODINGS  # Load encoding types

import hashlib

# Supported hash types
HASH_TYPES = ['md5', 'sha224', 'sha256', 'sha384', 'sha512']

try:  # to extend hash types if SHA3 is supported
    import sha3
except BaseException:
    print('\n * WARNING: SHA3 is not supported by your computer\n')
else:
    HASH_TYPES.extend(['sha3_224', 'sha3_256', 'sha3_384', 'sha3_512'])


class hash_machine(object):
    """
    Encapsulates the two basic hashi functionalities (the hash() and multi_hash() functions below)
    used for merkle-tree construction and validating merkle-proofs respectively.

    Sole purpose of this class is to fix at construction the hash and encoding types used for encrypting,
    so that these parameters need not be redefined every time a hash functionality is invoked; instances
    of this class are thus to be initialized with every new construction of a merkle-tree or every time
    a proof validation is about to be performed
    """

    # -------------------------------- Construction --------------------------

    def __init__(self, hash_type='sha256', encoding='utf-8', security=True):
        """
        :param hash_type : <str>  hash algorithm to be used by the machine; must be among the elements of the HASH_TYPES
                                  global variable (upper- or mixed-case with '-' instead of '_' allowed), otherwise an
                                  exception is thrown. Defaults to `sha256` if unspecified
        :param encoding  : <str>  encoding algorithm to be used by machine before hashing; must be among the elements of the
                                  ENCODINGS global variable (upper- or mixed-case with '-' instead of '_' allowed), otherwise an
                                  exception is thrown. Defaults to `utf_8` if unspecified
        :param security  : <bool> defaults to True; plays role only if hash and encoding types are sha256 and utf-8 respec-
                                  tively. In this case, security standards are applied against second-preimage attack, i.e.,
                                  single, resp. double arguments of the hash() function will be prepended with \x00, resp.
                                  \x01 before hashing.
        """

        # Hash algorithm used by the machine
        self.HASH = hash_machine.select_hash_algorithm(
            hash_type=hash_type.lower().replace('-', '_'))

        # Encoding type used by this machine before hashing
        self.ENCODING = hash_machine.select_encoding(
            encoding=encoding.lower().replace('-', '_'))

        # Plays role only if hash and endoding types are SHA256 resp. UTF-8
        self.SECURITY = security
        if self.SECURITY and self.HASH == hashlib.sha256 and self.ENCODING == 'utf_8':
            # ~ Security prefices will be prepended before hashing for defence against
            # ~ second-preimage attack
            self.PREFIX_0, self.PREFIX_1 = '\x00', '\x01'

    @staticmethod
    def select_hash_algorithm(hash_type):
        """
        Selects hash function according to inserted type

        :param hash_type : <str> must be among the hard-coded strings contained in the HASH_TYPES global variable;
                           otherwise an exception is raised
        :returns         : <builtin_funciton_or_method> the corressponding hash algorithm; e.g. hashlib.sha256 for
                           `hash_type` equal to 'sha256'
        """
        if hash_type in HASH_TYPES:
            return getattr(hashlib, hash_type)
        else:
            raise Exception(
                '\n\n * Hash type {hash_type} is not supported\n'.format(hash_type=hash_type))

    @staticmethod
    def select_encoding(encoding):
        """
        Throws relevant exception if the inserted encoding type is not supported

        :param encoding : <str> must be among the hard-coded strings contained in the ENCODINGS global variable;
                                otherwise an exception is raised
        :returns        : <str> e.g., 'utf_8'
        """
        if encoding in ENCODINGS:
            return encoding
        else:
            raise Exception(
                '\n\n * Encoding type {encoding} is not supported\n'.format(encoding=encoding))

    def security_mode_activated(self):
        """
        Returns True iff genuine security standards are activated, i.e., `self.SECURITY` is True
        along with hash and ecoding types of the machine being SHA256, resp. UTF-8

        returns : <bool>
        """
        return self.SECURITY and self.HASH == hashlib.sha256 and self.ENCODING == 'utf_8'

    # ------------------------------ Hash tools ------------------------------

    def hash(self, first, second=None):
        """
        Core hash functionality (single or double argument)

        Returns the hash of the object occuring by concatenation of arguments in the given order;
        if only one argument is passed in, then the hash of this single argument is returned.

        :param first  : <str> or <bytes> or <bytearray>
        :param second : <str> (valid hex) optional; if provided, then `first` must also be of <str> (valid hex) type
        :returns      : <str> (valid hex)
        """

        if not second:  # one arg case

            if isinstance(first, (bytes, bytearray)):
                # bytes-like input

                if self.security_mode_activated():
                    # Apply security stadards
                    return self.HASH(
                        bytes(
                            self.PREFIX_0,
                            encoding=self.ENCODING) +
                        first).hexdigest()

                # No security standards
                return self.HASH(first).hexdigest()

            # Non bytes-like input

            if self.security_mode_activated():

                # Apply security standards
                return self.HASH(
                    bytes(
                        '{}{}'.format(
                            self.PREFIX_0,
                            first),
                        encoding=self.ENCODING)).hexdigest()

            # No security standards
            return self.HASH(
                bytes(first, encoding=self.ENCODING)).hexdigest()

        # two args case

        if self.security_mode_activated():

            # Apply security standards
            return self.HASH(
                bytes(
                    '{}{}{}{}'.format(
                        self.PREFIX_1,
                        first,
                        self.PREFIX_1,
                        second),
                    encoding=self.ENCODING)).hexdigest()

        # No security standards
        return self.HASH(
            bytes(
                '{}{}'.format(
                    first,
                    second),
                encoding=self.ENCODING)).hexdigest()

    def multi_hash(self, signed_hashes, start):
        """
        Repeated application of the core hash() function over a list of strings or byte-like objects
        parenthesized in pairs as specified by accompanying signs

        Example: calling

            multi_hash(
                signed_hashes=[(+1, 'a'), (+1, 'b'), (-1, 'c'), (-1, 'd')],
                start=1
            )

        returns

            hash(hash('a' + hash('b' + 'c')) + 'd')

        :param signed_hashes : <list [of (+1/-1, <str> or <bytes> or <bytearray)]>, the sign +1 or -1
                               indicating pairing with the right or left neighbour respectively
        :param start         : <int> starting position for application of the hash() function
        :returns             : <str> result of calculation, or None if the argument `signed_hashes` was []
        """

        # Make a copy, so that input is not shrink-destroyed during calculation
        signed_hashes = signed_hashes[:]

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


# -------------------------------- End of class --------------------------
