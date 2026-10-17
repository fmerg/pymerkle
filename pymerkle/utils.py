def floor_log2(n):
    """
    Floor of base 2 logarithm

    .. note:: This is the exponent of the largest power of two which is less than
        or equal to the provided integer (zero for zero).

    :param n: non-negative integer
    :type n: int
    :rtype: int
    """
    return max(n.bit_length() - 1, 0)


def binary_exponents(n):
    """
    Returns in ascending order the exponents corresponding to the binary
    decomposition of the provided integer.

    :param n: non-negative integer
    :type n: int
    :rtype: list[int]
    """
    return [p for p in range(n.bit_length()) if n >> p & 1]
