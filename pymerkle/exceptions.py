"""
"""


class LeafConstructionError(BaseException):
    """Raised when arguments are not as prescribed upon construction of a leaf
    """
    pass


class NoChildException(BaseException):
    """Raised when the non-existent child of a node is requested
    """
    pass


class NoDescendantException(BaseException):
    """Raised when the non-existent descentant of a node is requested
    (i.e., with a descendancy-degree exceeding current possibilities)
    """


class NoParentException(BaseException):
    """Raised when the non-existent left or right parent of a node is invoked
    """
    pass


class EmptyTreeException(BaseException):
    """Raised when the root or the root-hash of an empty Merkle-tree is requested
    """
    pass

class EmptyPathException(BaseException):
    """Raised when the .multi_hash() method is called with an empty `signed_hashes` argument
    """
    pass

class NotSupportedEncodingError(BaseException):
    """Raised when a hash-machine or a Merkle-tree with unsupported encoding-type is requested
    """
    pass


class NotSupportedHashTypeError(BaseException):
    """Raised when a hash-machine or a Merkle-tree with unsupported hash-type is requested
    """
    pass


class NoPathException(BaseException):
    """Raised when a proof-path is requested for valid parameters that cannot be generated
    """
    pass

class NoSubtreeException(BaseException):
    """Raised when a full-binary subtree is requested for valid parameters that does not exist
    """
    pass

class NoPrincipalSubrootsException(BaseException):
    """Raised when a sequence of subroots corresponding for valid parameters that does not exist
    """
    pass

class InvalidProofRequest(BaseException):
    """Raised when a proof is requested with arguments whose type is not as prescribed
    """
    pass

class InvalidTypesException(BaseException):
    """Raised when an inclusion-test is requested with arguments whose type is not as prescribed
    """
    pass

class InvalidComparison(BaseException):
    """Raised when a Merkle-tree is compared with an object that is not instance of the ``MerkleTree`` class
    """
    pass

class WrongJSONFormat(BaseException):
    """Raised when the deserialized object is not as expected
    """
    pass
