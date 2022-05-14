"""
Provides the exceptions used accross the *pymerkle* library.
"""


class InvalidProof(Exception):
    """
    Raised when a Merkle-proof is found to be invalid.
    """
    pass


class EmptyPathException(Exception):
    """
    Raised when *HashEngine.multi_hash()* is called with an empty argument.
    """
    pass


class NoAncestorException(Exception):
    """
    Raised when the non-existent ancestor of a node is requested
    (i.e., with a descendancy-degree exceeding current possibilities).
    """


class NoPathException(Exception):
    """
    Raised when no path exists for the provided parameters.
    """
    pass


class NoPrincipalSubroots(Exception):
    """
    Raised when no sequence of subroots exists for the provided parameters.
    """
    pass


class UnsupportedEncoding(Exception):
    """
    Raised when a hashing engine with unsupported encoding-type is requested.
    """
    pass


class UnsupportedHashType(Exception):
    """
    Raised when a hashing engine with unsupported hash-type is requested.
    """
    pass


class UndecodableArgumentError(Exception):
    """
    Raised when an argument is passed into the hash function,
    which cannot be decoded under the configured encoding type.
    """
    pass


class UndecodableRecord(Exception):
    """
    Raised when raw-bytes mode is disabled and an argument is passed
    which cannot be decoded under the configured encoding type.
    """
    pass


class WrongJSONFormat(Exception):
    """
    Raised when a deserialized object is not as expected
    """
    pass
