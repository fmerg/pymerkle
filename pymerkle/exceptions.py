"""Provides the exceptions used accross the *pymerkle* library.
"""


class InvalidMerkleProof(Exception):
    """
    Raised when a Merkle-proof is found to be invalid.
    """
    pass


class EmptyTreeException(Exception):
    """
    Raised when the root or root-hash of an empty Merkle-tree is requested.
    """
    pass


class EmptyPathException(Exception):
    """
    Raised when *HashEngine.multi_hash()* is called with an empty argument.
    """
    pass


class InvalidComparison(Exception):
    """
    Raised when a Merkle-tree is compared with an object that is not
    instance of the *MerkleTree* class.
    """
    pass


class LeafConstructionError(Exception):
    """
    Raised upon construction of a leaf if the provided arguments
    are not as prescribed.
    """
    pass


class NoParentException(Exception):
    """
    Raised when the non-existent parent of a node is invoked.
    """
    pass


class NoAncestorException(Exception):
    """
    Raised when the non-existent ancestor of a node is requested
    (i.e., with a descendancy-degree exceeding current possibilities).
    """


class NoChildException(Exception):
    """
    Raised when the non-existent left or right child of a node is invoked.
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


class NoSubtreeException(Exception):
    """
    Raised when no full-binary subtree exists for the provided parameters.
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
