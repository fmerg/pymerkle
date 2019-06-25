"""
"""


class LeafConstructionError(BaseException):
    """Raised when arguments are not as prescribed upon construction of a leaf (``nodes.Leaf``)
    """
    pass


class NoChildException(BaseException):
    """Raised when the non-existent child property of a node (``nodes._Node``) is invoked
    """
    pass


class NoDescendantException(BaseException):
    """Raised when the non-existent descentant of a node is requested (i.e., with a
    descendancy-degree that exceeds possibilities)
    """


class NoParentException(BaseException):
    """Raised when the non-existent left or right parent of a node is invoked
    """
    pass


class EmptyTreeException(BaseException):
    """Raised for example when the root-hash of an empty Merkle-tree is requested
    """
    pass


class NotSupportedEncodingError(BaseException):
    """Raised when a hash-machine (``hashing.hash_machine``) or a Merkle-Tree (``tree.MerkleTree``)
    with unsupported encoding type is requested
    """
    pass


class NotSupportedHashTypeError(BaseException):
    """Raised when a hash-machine (``hashing.hash_machine``) or a Merkle-Tree (``tree.MerkleTree``)
    with unsupported hash type is requested
    """
    pass


class NoPathException(BaseException):
    """Raised when the proof-path requested from a Merkle-tree for specific parameters cannot be
    generated (indicates authorization failure from the client's side)
    """
    pass

class InvalidProofRequest(BaseException):
    """Raised when a proof is requested with arguments whose type is not as prescribed
    """
    pass

class NoSubtreeException(BaseException):
    """Raised when the full binary subtree of a specified height and based on a specified leaf
    does not exist
    """
    pass

class NoPrincipalSubrootsException(BaseException):
    """Raised when the sequence of subroots corresponding to a specified length do not exist
    """
    pass

class InvalidTypesException(BaseException):
    """Raised when the types of arguments given for consistency proof or inclusion tests is not as prescribed
    """
    pass

class InvalidComparison(BaseException):
    """Raised when a Merkle-tree is compared with an object that is not instance of the MerkleTree class
    """
    pass
