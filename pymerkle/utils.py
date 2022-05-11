"""Provides standalone utilities invoked across the *pymerkle* library
"""

from math import log, log10
import uuid


NONE = '[None]'


def generate_uuid():
    return str(uuid.uuid1())


def log_2(num):
    """Computes and returns the base 2 logarithm of the provided number
    (i.e., the greatest power of 2 equal to or smaller than *num*)

    .. note:: Given any *balanced* binary tree, whose number of leaves
        equals the provided argument, this function returns the tree's
        height (i.e., the depth of its left-most branch)

    :param num: the number whose logarithm is to be computed
    :type num: int
    :returns: the computed logarithm
    :rtype: int

    .. note:: By convention, it returns 0 for the zero argument

    :raises ValueError: for arguments smaller than zero
    """
    return int(log(num, 2)) if num != 0 else 0


def decompose(num):
    """Additive decomposition in decreasing powers of 2

    Given a positive integer uniquely decomposed as

    ``2 ^ p_m + ... + 2 ^ p_1, p_m > ... > p_1 >= 0``

    then the tuple *(p_m, ..., p_1)* is returned

    :Example:

    >>> 45 == 2 ** 5 + 2 ** 3 + 2 ** 2 + 1
    True
    >>>
    >>> decompose(45)
    (5, 3, 2, 0)

    :param num: the number to be decomposed
    :type num: int
    :returns: powers of 2 in decreasing order
    :rtype: tuple of integers

    .. note:: Returns the nonsensical empty tuple for
        arguments equal to or smaller than zero
    """
    powers = []
    append = powers.append
    while num > 0:
        power = log_2(num)
        append(power)
        num -= 2 ** power
    return tuple(powers)


def stringify_path(path, encoding):
    """Returns a string representing the provided sequence of signed hashes.

    .. note:: Printed hashes occure after decoding the given ones in
        accordance under the provided encoding type

    :param path: sequence of signed hashes
    :type path: tuple of (+1/-1, bytes) or (+1/-1, str)
    :param encoding: encoding type to be used for decoding
    :type encoding: str
    :rtype: str
    """
    def order_of_magnitude(num): return int(log10(num)) if num != 0 else 0
    def get_with_sign(num): return f'{"+" if num >= 0 else ""}{num}'
    pairs = []
    pair_template = '\n{left}[{index}]{middle}{sign}{right}{digest}'
    for index, curr in enumerate(path):
        pairs.append(
            pair_template.format(left=(7 - order_of_magnitude(index)) * ' ',
                                 index=index,
                                 middle=3 * ' ',
                                 sign=get_with_sign(curr[0]),
                                 right=3 * ' ',
                                 digest=curr[1].decode(encoding) if not isinstance(curr[1], str)
                                 else curr[1]))
    return ''.join(pairs)
