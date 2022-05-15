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
