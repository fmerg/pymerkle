"""
Layout of Merkle-proofs, i.e., the leaf ranges whose root-hashes make up the
path of hashes along with the bits specifying how to resolve it. The layout
depends only on the leaf index and tree sizes, not on the hashes themselves,
so that it is shared by proof generation and verification.

Ranges are pairs ``(start, end)`` of leaf positions counting from zero, the
end being exclusive.
"""

from pymerkle.utils import log2


def split(width):
    """
    Returns the number of leaves under the left child of the root of a tree
    with the provided number of leaves, i.e., the largest power of two which
    is strictly less than the provided width.

    :param width: number of leaves (greater than one)
    :type width: int
    :rtype: int
    """
    k = 1 << log2(width)

    return k >> 1 if k == width else k


def inclusion_layout(pos, size):
    """
    Layout of the inclusion proof for the leaf located at the provided
    position against the state corresponding to the provided size.

    :param pos: leaf position counting from zero
    :type pos: int
    :param size: number of leaves
    :type size: int
    :returns: rule and ranges whose root-hashes make up the path, the first
        one being the base leaf
    :rtype: (list[int], list[(int, int)])
    """
    start, end, bit = 0, size, 0
    steps = []
    while end - start > 1:
        k = split(end - start)

        if pos < start + k:
            steps += [(bit, (start + k, end))]
            end = start + k
            bit = 0
        else:
            steps += [(bit, (start, start + k))]
            start += k
            bit = 1

    steps.reverse()
    rule = [bit] + [b for (b, _) in steps]
    ranges = [(pos, pos + 1)] + [r for (_, r) in steps]

    return rule, ranges


def consistency_layout(size1, size2):
    """
    Layout of the consistency proof between the states corresponding to the
    provided sizes.

    :param size1: number of leaves for prior state
    :type size1: int
    :param size2: number of leaves for later state
    :type size2: int
    :returns: rule, subset and ranges whose root-hashes make up the path, the
        subset indicating those resolving to the prior state
    :rtype: (list[int], list[int], list[(int, int)])
    """
    start, offset, width, bit = 0, size1, size2, 0
    steps = []
    while not (offset == width or (offset == 0 and width == 1)):
        k = split(width)

        if offset < k:
            steps += [(bit, 0, (start + k, start + width))]
            width = k
            bit = 0
        else:
            steps += [(bit, 1, (start, start + k))]
            start += k
            offset -= k
            width -= k
            bit = 1

    if offset == width:
        mask, base = 1, (start, start + width)
    else:
        mask, base = 0, (start, start + 1)

    steps.reverse()
    rule = [bit] + [b for (b, _, _) in steps]
    subset = [mask] + [m for (_, m, _) in steps]
    ranges = [base] + [r for (_, _, r) in steps]

    return rule, subset, ranges
