def log2(n: int) -> int:
    """
    Base 2 logarithm

    .. note:: This is the exponent of the largest power of two which is less than
        or equal to the provided integer.

    :param n: non-negative integer
    :type n: int
    :rtype: int
    """

    if (n < 0):
        raise ArithmeticError('n must be a non-negative integer')

    k: int = 0
    while n >> 1:
        k += 1
        n >>= 1

    return k


def decompose(n: int) -> list[int]:
    """
    Returns in respective order the exponents corresponding to the binary
    decomposition of the provided integer.

    :param n: non-negative integer
    :type n: int
    :rtype: list[int]
    """
    if (n < 0):
        raise ArithmeticError('n must be a non-negative integer')

    exponents: list[int] = []

    i: int = 1
    while i < n + 1:
        if i & n:
            p: int = -1
            j: int = i
            while j:
                j >>= 1
                p += 1
            exponents += [p]

        i <<= 1

    return exponents
