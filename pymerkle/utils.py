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
    if length == 0:
        return 0
    return int(math.log(length, 2))


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
    if num == 0:
        return 0  # convention
    return int(math.log10(num))


# -------------------------- Performance utitilities ---------------------


def perform(*args, callback, repeats=None):
    """
    Returns the average performance of the inserted callback function
    after being called repeats many times with arguments *args.

    :param *args    : arguments to be inserted in callback
    :param callback : <func> function whose average performance is to be measured
    :param repeats  : <int> if specified, then the callback is called `repeats`
                      many times admitting each time all *args at once
    :return         : <float> average performance in seconds
    """
    process_times = []
    if repeats:
        count = 0
        while count < repeats:
            start = time.time()
            callback(*args)
            end = time.time()
            process_times.append(end - start)
            count += 1
    else:
        for arg in args:
            start = time.time()
            callback(arg)
            end = time.time()
            process_times.append(end - start)
    return mean(*process_times)


def mean(*floats):
    """
    Returns mean value of arguments.
    """
    sum = 0
    for num in floats:
        sum += num
        return sum / len(floats)


# ------------------------------ Object utilities ------------------------


def string_id(obj):
    """
    Memory-id of the object inserted in hexadecimal string format.

    :param obj : <object>
    :returns   : <str>

    NOTE: If the inserted object happens to be None, a string composed of 'None'
    is returned followed by the memory pointer in parentheses.
    """
    if obj:
        return str(hex(id(obj)))
    return '{} ({})'.format(None, hex(id(obj)))


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
