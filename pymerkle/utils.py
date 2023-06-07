def log2(n):
    """
    Base 2 logarithm

    .. note:: This is the exponent of the largest power of 2 which is less than
        or equal to the provided integer

    :param n: non-negative integer
    :type n: int
    :rtype: int
    """
    k = 0
    while n >> 1:
        k += 1
        n >>= 1

    return k


def decompose(n):
    """
    Returns in respective order the exponents corresponding to the binary
    decomposition of the provided integer

    :param n: non-negative integer
    :type n: int
    :rtype: list[int]
    """
    exponents = []

    i = 1
    while i < n + 1:
        if i & n:
            p = -1
            j = i
            while j:
                j >>= 1
                p += 1
            exponents += [p]

        i <<= 1

    return exponents
