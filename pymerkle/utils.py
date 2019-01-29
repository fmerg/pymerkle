"""
Contains math and format utils invoked across the library
"""

import math


def log_2(num):
    """Computes and returns the base 2 logarithm of the given number (i.e.,
    the greatest power of 2 equal to or smaller than ``num``)

    :param num: the number whose logarithm is to be computed
    :type num:  int
    :returns:   the computed logarithm
    :rtype:     ``int``

    :raises ValueError: for arguments smaller than zero

    .. note:: By convention, it returns 0 for zero argument
    """
    return 0 if num == 0 else int(math.log(num, 2))


def decompose(num):
    """Additive decomposition in decreasing powers of 2

    :param num: the number to be decomposed
    :type num:  int
    :returns:   powers of 2 in decreasing order
    :rtype:     ``tuple`` of integers

    :Example:

    >>> from pymerkle.utils import decompose
    >>> decompose(2**5 + 2**3 + 2**2 + 1)
    (5, 3, 2, 0)

    .. note:: Returns the nonsensical empty tuple for arguments equal to or smaller than zero
    """
    powers = []
    while num > 0:
        power = log_2(num)
        num -= 2**power
        powers.append(power)
    return tuple(powers)


def stringify_path(signed_hashes):
    """Returns a stringified version of the inserted sequence of signed hashes

    :param signed_hashes: a sequence of signed hashes
    :type signed_hashes:  tuple of (+1/-1, str) pairs
    :rtype:               ``str``

    .. note:: The output of this function is to be passed into the ``print()`` function
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
                 '{hash}').
                format(i=i, sign=get_with_sign(elem[0]), hash=elem[1]))
        return ''.join(elem for elem in stringified_elems)
    return ''  # input was None
