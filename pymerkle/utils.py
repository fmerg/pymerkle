import time
import math
import sys
import os

# ------------------------------ Math utilities --------------------------


def log_2(length):
    """
    Logarithm with base 2

    :param length : <int>
    :returns      : <int>

    Returns the logarithm of the greatest power of 2 equal to or smaller than `length`

    NOTE: Throws

    ValueError: math domain IndexError

    for arguments smaller than zero.
    """
    return 0 if length == 0 else int(math.log(length, 2))


def powers_of(integer):
    """
    Additive decomposition in decreasing powers of 2

    :param integer : <int>
    :returns       : <list [of <int>]>

    NOTE: Returns the nonsensical empty list [] for any argument equal to
    or smaller than zero.
    """
    powers = []
    while integer > 0:
        power = log_2(integer)
        integer -= 2**power
        powers.append(power)
    return powers


def get_with_sign(num):
    """
    param num : <int>
    returns   : <str>
    """
    if num >= 0:
        sign = '+'
    else:
        sign = '-'
    return sign + str(abs(num))


def order_of_magnitude(num):
    """
    param num : <int>
    return    : <int>
    """
    return 0 if num == 0 else int(math.log10(num))


# ------------------------------ Object utilities ------------------------


def string_id(obj):
    """
    Memory-id of the object inserted in hexadecimal string format.

    :param obj : <object>
    :returns   : <str>

    NOTE: If the inserted object happens to be None, a string composed of 'None'
    is returned followed by the memory pointer in parentheses.
    """
    return str(hex(id(obj))) if obj else '{} ({})'.format(None, hex(id(obj)))


# --------------------------- Block/Unblock printing ---------------------


def block_print():
    """
    Blocks printing
    """
    sys.stdout = open(os.devnull, 'w')


def allow_print():
    """
    Unblocks printing
    """
    sys.stdout = sys.__stdout__
