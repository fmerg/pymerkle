"""
Utilities
"""

from math import log, log10
import uuid


def generate_uuid():
    """
    :returns: UUID1 universal identifier
    :rtype: str
    """
    return str(uuid.uuid1())


def log_2(num):
    """
    Computes the base 2 logarithm of the provided value (i.e., the greatest
    power of 2 equal to or smaller than *num*).

    .. note:: Given a left-balanced binary tree whose number of leaves equals
        the provided value, this function returns the tree's height (i.e.,
        the depth of its leftmost branch).

    .. note:: By convention, this function returns 0 for the zero argument.

    :param num: the integer whose logarithm is to compute
    :type num: int
    :returns: base 2 logarithm of the provided integer
    :rtype: int

    :raises ValueError: for arguments smaller than zero
    """
    return int(log(num, 2)) if num != 0 else 0


def decompose(num):
    """
    Additive decomposition in decreasing powers of 2.

    Given a positive integer uniquely decomposed as

    ``2 ^ p_m + ... + 2 ^ p_1, p_m > ... > p_1 >= 0``

    then the sequence ``(p_m, ..., p_1)`` is returned.

    .. note:: Returns the nonsensical empty list for arguments equal to or
        smaller than zero.

    :Example:

    >>> 45 == 2 ** 5 + 2 ** 3 + 2 ** 2 + 1
    True
    >>>
    >>> decompose(45)
    [5, 3, 2, 0]

    :param num: the integer to decompose
    :type num: int
    :returns: powers of 2 in decreasing order
    :rtype: list
    """
    powers = []
    while num > 0:
        power = log_2(num)
        powers += [power]
        num -= 2 ** power
    return powers
