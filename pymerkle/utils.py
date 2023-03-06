def log2(n):
    """
    Logarithm with base 2

    :param n: non negative integer
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
    Returns the exponents corresponding to the binary decomposition of the
    provided integer in increasing order

    :Example:

    >>> 45 == 2 ** 0 + 2 ** 2 + 2 ** 3 + 2 ** 5
    True
    >>>
    >>> decompose(45)
    [0, 2, 3, 5]

    :param n: non negative integer
    :type n: int
    :rtype: list[int]
    """
    out = []

    i = 1
    while i <= n:
        if i & n:
            p = -1
            j = i
            while j:
                j >>= 1
                p += 1
            out += [p]

        i <<= 1

    return out
