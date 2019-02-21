"""
Provides utilities invoked across the library
"""

import math


def log_2(num):
    """Computes and returns the base *2* logarithm of the given number (i.e.,
    the greatest power of *2* equal to or smaller than ``num``)

    .. note:: Given any *balanced* binary tree, whose number of leaves equals
              the inserted one, this function returns the tree's height
              (i.e., the depth of its *left-most* branch)

    :param num: the number whose logarithm is to be computed
    :type num:  int
    :returns:   the computed logarithm
    :rtype:     int

    .. note:: By convention, it returns 0 for zero argument

    :raises ValueError: for arguments smaller than zero
    """
    return 0 if num == 0 else int(math.log(num, 2))


def decompose(num):
    """Additive decomposition in decreasing powers of 2

    Given a positive integer uniquely decomposed as

    ``2 ^ (p_m) + ... + 2 ^ (p_1),  p_m > ... > p_1 >= 0``

    then the tuple ``(p_m, ..., p_1)`` is returned

    :Example:

    >>> num = 45
    >>> num == 2**5 + 2**3 + 2**2 + 1
    True
    >>>
    >>> decompose(num)
    (5, 3, 2, 0)

    :param num: the number to be decomposed
    :type num:  int
    :returns:   powers of *2* in decreasing order
    :rtype:     tuple of integers

    .. note:: Returns the nonsensical empty tuple for arguments equal to or
              smaller than zero
    """
    powers = []
    while num > 0:
        power = log_2(num)
        num -= 2**power
        powers.append(power)
    return tuple(powers)


def stringify_path(signed_hashes, encoding):
    """Returns a nicely stringified version of the inserted sequence of signed hashes.

    The printed hashes are hexadecimals, occuring after decoding the given ones according
    to the inserted encoding type.

    .. note:: The output of this function is to be passed into the ``print`` function

    :param signed_hashes: a sequence of signed hashes
    :type signed_hashes:  tuple of (+1/-1, bytes) pairs
    :param encoding:      type to be used for decoding
    :type encoding:       str
    :rtype:               str
    """
    def order_of_magnitude(num): return 0 if num == 0 else int(math.log10(num))

    def get_with_sign(num): return str(num) if num < 0 else '+' + str(num)

    if signed_hashes is not None:
        stringified_elems = []
        for i in range(len(signed_hashes)):
            elem = signed_hashes[i]
            stringified_elems.append(
                ('\n' +
                 (7 - order_of_magnitude(i)) * ' ' +
                 '[{i}]' +
                 3 * ' ' +
                 '{sign}' +
                 2 * ' ' +
                 '{hash}'). format(
                     i=i,
                     sign=get_with_sign(elem[0]),
                     hash=elem[1].decode(encoding=encoding)
                     if not isinstance(elem[1], str) else elem[1]))
        return ''.join(elem for elem in stringified_elems)
    return ''  # input was None
