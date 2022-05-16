class InvalidProof(Exception):
    """
    Raised when a Merkle-proof is found to be invalid.
    """
    pass


class EmptyPathException(Exception):
    """
    Raised when an empty path of hashes is fed to a hashing engine.
    """
    pass


class NoPathException(Exception):
    """
    Raised when no path of hashes exists for the provided parameters.
    """
    pass


class NoPrincipalSubroots(Exception):
    """
    Raised when no sequence of principal subroots is found for the provided
    parameters.

    .. note:: By *principal subroot* is meant the root of a full binary subtree
        of maximal length.
    """
    pass


class UnsupportedParameter(Exception):
    """
    Raised when a hashing engine with unsupported paramter is requested.
    """
    pass
