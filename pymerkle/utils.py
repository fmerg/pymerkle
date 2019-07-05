"""Provides standalone utilities invoked across the library
"""

import math


def log_2(num):
    """Computes and returns the base *2* logarithm of the given number (i.e., the greatest power of *2*
    equal to or smaller than ``num``)

    .. note:: Given any *balanced* binary tree, whose number of leaves equals the inserted argument,
              this function returns the tree's height (i.e., the depth of its *left-most* branch)

    :param num: the number whose logarithm is to be computed
    :type num:  int
    :returns:   the computed logarithm
    :rtype:     int

    .. note:: By convention, it returns ``0`` for the zero argument

    :raises ValueError: for arguments smaller than zero
    """
    return int(math.log(num, 2)) if num != 0 else 0


def decompose(num):
    """Additive decomposition in decreasing powers of 2. Given a positive integer uniquely decomposed as

    ``2 ^ (p_m) + ... + 2 ^ (p_1),  p_m > ... > p_1 >= 0``

    then the tuple ``(p_m, ..., p_1)`` is returned

    :Example:

    >>> 45 == 2**5 + 2**3 + 2**2 + 1
    True
    >>>
    >>> decompose(45)
    (5, 3, 2, 0)

    :param num: the number to be decomposed
    :type num:  int
    :returns:   powers of *2* in decreasing order
    :rtype:     tuple of integers

    .. note:: Returns the nonsensical empty tuple for arguments equal to or smaller than zero
    """

    powers = []
    while num > 0:
        _power = log_2(num)
        num -= 2**_power
        powers.append(_power)

    return tuple(powers)


def stringify_path(signed_hashes, encoding):
    """Returns a nicely stringified version of the inserted sequence of signed checksums.

    The printed checksums occure after decoding the given ones according to the inserted encoding type.

    :param signed_hashes: a sequence of signed hashes
    :type signed_hashes:  tuple of (+1/-1, <bytes>) or (+1/-1, <string>) pairs
    :param encoding:      encoding type to be used for decoding
    :type encoding:       str
    :rtype:               str
    """

    order_of_magnitude = lambda num: int(math.log10(num)) if num != 0 else 0
    get_with_sign      = lambda num: '%s%d' % ('+' if num >=0 else '', num)

    stringified_pairs = []

    for i in range(len(signed_hashes)):

        pair = signed_hashes[i]

        stringified_pairs.append(
            '\n%s[{i}]%s{sign}%s{hash}'
            .format(
                i=i,
                sign=get_with_sign(pair[0]),
                hash=pair[1].decode(encoding=encoding) if not isinstance(pair[1], str) else pair[1]
            ) % (
                    (7 - order_of_magnitude(i)) * ' ',
                    3 * ' ',
                    2 * ' '
            )
        )

    return ''.join(_ for _ in stringified_pairs)
