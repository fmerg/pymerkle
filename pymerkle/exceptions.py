"""
"""


class LeafConstructionError(BaseException):
    """Raised when arguments are not as prescribed
    upon construction of a leaf (``nodes.Leaf``)
    """
    pass


class NoChildException(BaseException):
    """Raised when the non-existent child property of a node is invoked
    """
    pass


class NoDescendantException(BaseException):
    """Raised when the non-existent descentant of a node is requested
    (i.e., with a descendancy-degree that exceeds possibilities)
    """


class NoParentException(BaseException):
    """Raised when the non-existent left or right parent of a node is invoked
    """
    pass
