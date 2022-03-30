"""
Provides the exceptions used accross the *pymerkle* library
"""

class InvalidMerkleProof(BaseException):
    """
    Raised when a Merkle-proof is found to be invalid
    """
    pass

class EmptyTreeException(BaseException):
    """
    Raised when the root or root-hash of an empty Merkle-tree is requested
    """
    pass


class EmptyPathException(BaseException):
    """
    Raised when *HashMachine.multi_hash()* is called with an empty argument
    """
    pass


class InvalidComparison(BaseException):
    """
    Raised when a Merkle-tree is compared with an object that is not
    instance of the *MerkleTree* class
    """
    pass


class InvalidChallengeError(BaseException):
    """
    Raised when a challenge is posed, whose structure is not as prescribed
    """
    pass


class InvalidTypes(BaseException):
    """
    Raised when an inclusion-test is requested with arguments whose types
    are not as prescribed
    """
    pass


class LeafConstructionError(BaseException):
    """
    Raised upon construction of a leaf if the provided arguments
    are not as prescribed
    """
    pass


class NoChildException(BaseException):
    """
    Raised when the non-existent child of a node is invoked
    """
    pass


class NoDescendantException(BaseException):
    """
    Raised when the non-existent descentant of a node is requested
    (i.e., with a descendancy-degree exceeding current possibilities)
    """


class NoParentException(BaseException):
    """
    Raised when the non-existent left or right parent of a node is invoked
    """
    pass


class NoPathException(BaseException):
    """
    Raised when no proof-path exists for the provided parameters
    """
    pass


class NoPrincipalSubroots(BaseException):
    """
    Raised when no sequence of subroots exists for the provided parameters
    """
    pass


class NoSubtreeException(BaseException):
    """
    Raised when no full-binary subtree exists for the provided parameters
    """
    pass


class UnsupportedEncoding(BaseException):
    """
    Raised when a hash-machine with unsupported encoding-type is requested
    """
    pass


class UnsupportedHashType(BaseException):
    """
    Raised when a hash-machine with unsupported hash-type is requested
    """
    pass


class UndecodableArgumentError(BaseException):
    """
    Raised when an argument is passed into the hash function,
    which cannot be decoded by the machine's configured encoding type
    """
    pass


class UndecodableRecord(BaseException):
    """
    Raised when raw-bytes mode is disabled and an argument is passed
    into the constructor of *Leaf* or *Node*, which cannot be
    decoded under the configured encoding type
    """
    pass


class WrongJSONFormat(BaseException):
    """
    Raised when a deserialized object is not as expected
    """
    pass
