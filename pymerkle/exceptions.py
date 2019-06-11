"""
"""


class NodeConstructionError(BaseException):
    """To be raised when arguments are not as prescribed upon
    construction of ``nodes.Node`` instances
    """
    pass


class LeafConstructionError(BaseException):
    """To be raised when arguments are not as prescribed upon
    construction of ``nodes.Leaf`` instances
    """
    pass
