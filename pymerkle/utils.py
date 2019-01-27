"""Contains math and format utils invoked across the library"""

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

    :Example:

    >>> from pymerkle.utils import stringify_path
    >>> stringified_path = stringify_path(((+1, 'f0c5657b4c05a6538aef498ad9d92c28759f20c6ab99646a361f2b5e328287da'), (-1, '11e1f558223f4c71b6be1cecfd1f0de87146d2594877c27b29ec519f9040213c'), (-1, 'a63a34abf5b5dcbe1eb83c2951395ff8bf03ee9c6a0dc2f2a7d548f0569b4c02')))
    >>> print(stringified_path)
    '\n       [0]   +1  f0c5657b4c05a6538aef498ad9d92c28759f20c6ab99646a361f2b5e328287da\n       [1]   -1  11e1f558223f4c71b6be1cecfd1f0de87146d2594877c27b29ec519f9040213c\n       [2]   -1  a63a34abf5b5dcbe1eb83c2951395ff8bf03ee9c6a0dc2f2a7d548f0569b4c02'
    >>>
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
