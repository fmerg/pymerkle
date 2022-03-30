"""
Tests standalone utilities used across the *pymerkle* library
"""
import pytest
import itertools

from pymerkle import utils

# setup

logarithms = []
nums = []
mixed_powers = []

for p in tuple(range(0, 11)):                                                   # 0 <= p <= 10
    index_set = list(range(p))                                                  # [0, 1, ... p-1]
    for k in range(p + 1):                                                      # 0 <= k <= p
        for combination in itertools.combinations(index_set, k):
            combination = list(combination)

            # [i_1, ..., i_k, p], i_1 < ... < i_k < p
            combination.append(p)
            mixed_powers.append(combination)

            # 2 ^ i_1 + ... + 2 ^ i_k + 2 ^ p,   i_1 < ... < i_k < p,   0 <= p <= 10
            nums.append(sum((map(lambda x: 2 ** x, combination))))

            logarithms.append(p)


# log_2

def test_log_2_exception():
    """
    Test that log_2 raises ValueError for negative arguments
    """
    with pytest.raises(ValueError):
        utils.log_2(-1)


def test_log_2_zero_convention():
    """
    Test that log_2 evaluates to 0 for the zero argument
    """
    assert utils.log_2(0) == 0


@pytest.mark.parametrize("num, expected", zip(nums, logarithms))
def test_log_2(num, expected):
    """
    Tests log_2 evaluations for all possible
    combinations of powers from 0 to 10
    """
    assert utils.log_2(num) == expected


# decompose

def test_decompose_zero_convention():
    """
    Tests that decompose returns the nonsensical empty
    tuple for arguments equal to zero
    """
    assert utils.decompose(0) == ()


def test_decompose_negative_convention():
    """
    Test that decompose returns the nonsensical
    empty tuple for arguments smaller than zero
    """
    assert utils.decompose(-1) == ()


def reverseTupleFromList(_list):
    """
    Helper function for the next test session.
    Returns tuple from list in reverse order
    """
    _tuple = ()
    for elem in reversed(_list):
        _tuple += (elem, )
    return _tuple


@pytest.mark.parametrize("num, powers", zip(nums, mixed_powers))
def test_decompose(num, powers):
    """
    Test decompose for all possible combination of powers from 0 to 10
    """
    assert utils.decompose(num) == reverseTupleFromList(powers)


# stringify_path

def test_stringify_empty_path():
    assert utils.stringify_path((), 'utf_8') == ''

def test_stringify_bytes_path():
    assert utils.stringify_path(
        (
            (+1, bytes('3f824b56e7de850906e053efa4e9ed2762a15b9171824241c77b20e0eb44e3b8', 'utf-8')),
            (+1, bytes('4d8ced510cab21d23a5fd527dd122d7a3c12df33bc90a937c0a6b91fb6ea0992', 'utf-8')),
            (+1, bytes('35f75fd1cfef0437bc7a4cae7387998f909fab1dfe6ced53d449c16090d8aa52', 'utf-8')),
            (-1, bytes('73c027eac67a7b43af1a13427b2ad455451e4edfcaced8c2350b5d34adaa8020', 'utf-8')),
            (+1, bytes('cbd441af056bf79c65a2154bc04ac2e0e40d7a2c0e77b80c27125f47d3d7cba3', 'utf-8')),
            (+1, bytes('4e467bd5f3fc6767f12f4ffb918359da84f2a4de9ca44074488b8acf1e10262e', 'utf-8')),
            (-1, bytes('db7f4ee8be8025dbffee11b434f179b3b0d0f3a1d7693a441f19653a65662ad3', 'utf-8')),
            (-1, bytes('f235a9eb55315c9a197d069db9c75a01d99da934c5f80f9f175307fb6ac4d8fe', 'utf-8')),
            (+1, bytes('e003d116f27c877f6de213cf4d03cce17b94aece7b2ec2f2b19367abf914bcc8', 'utf-8')),
            (-1, bytes('6a59026cd21a32aaee21fe6522778b398464c6ea742ccd52285aa727c367d8f2', 'utf-8')),
            (-1, bytes('2dca521da60bf0628caa3491065e32afc9da712feb38ff3886d1c8dda31193f8', 'utf-8'))
        ),
        'utf_8'
    ) == '\n       [0]   +1   3f824b56e7de850906e053efa4e9ed2762a15b9171824241c77b20e0eb44e3b8\n\
       [1]   +1   4d8ced510cab21d23a5fd527dd122d7a3c12df33bc90a937c0a6b91fb6ea0992\n\
       [2]   +1   35f75fd1cfef0437bc7a4cae7387998f909fab1dfe6ced53d449c16090d8aa52\n\
       [3]   -1   73c027eac67a7b43af1a13427b2ad455451e4edfcaced8c2350b5d34adaa8020\n\
       [4]   +1   cbd441af056bf79c65a2154bc04ac2e0e40d7a2c0e77b80c27125f47d3d7cba3\n\
       [5]   +1   4e467bd5f3fc6767f12f4ffb918359da84f2a4de9ca44074488b8acf1e10262e\n\
       [6]   -1   db7f4ee8be8025dbffee11b434f179b3b0d0f3a1d7693a441f19653a65662ad3\n\
       [7]   -1   f235a9eb55315c9a197d069db9c75a01d99da934c5f80f9f175307fb6ac4d8fe\n\
       [8]   +1   e003d116f27c877f6de213cf4d03cce17b94aece7b2ec2f2b19367abf914bcc8\n\
       [9]   -1   6a59026cd21a32aaee21fe6522778b398464c6ea742ccd52285aa727c367d8f2\n\
      [10]   -1   2dca521da60bf0628caa3491065e32afc9da712feb38ff3886d1c8dda31193f8'

def test_stringify_string_path():
    assert utils.stringify_path(
        (
            (+1, '3f824b56e7de850906e053efa4e9ed2762a15b9171824241c77b20e0eb44e3b8'),
            (+1, '4d8ced510cab21d23a5fd527dd122d7a3c12df33bc90a937c0a6b91fb6ea0992'),
            (+1, '35f75fd1cfef0437bc7a4cae7387998f909fab1dfe6ced53d449c16090d8aa52'),
            (-1, '73c027eac67a7b43af1a13427b2ad455451e4edfcaced8c2350b5d34adaa8020'),
            (+1, 'cbd441af056bf79c65a2154bc04ac2e0e40d7a2c0e77b80c27125f47d3d7cba3'),
            (+1, '4e467bd5f3fc6767f12f4ffb918359da84f2a4de9ca44074488b8acf1e10262e'),
            (-1, 'db7f4ee8be8025dbffee11b434f179b3b0d0f3a1d7693a441f19653a65662ad3'),
            (-1, 'f235a9eb55315c9a197d069db9c75a01d99da934c5f80f9f175307fb6ac4d8fe'),
            (+1, 'e003d116f27c877f6de213cf4d03cce17b94aece7b2ec2f2b19367abf914bcc8'),
            (-1, '6a59026cd21a32aaee21fe6522778b398464c6ea742ccd52285aa727c367d8f2'),
            (-1, '2dca521da60bf0628caa3491065e32afc9da712feb38ff3886d1c8dda31193f8')
        ),
        'utf_8'
    ) == '\n       [0]   +1   3f824b56e7de850906e053efa4e9ed2762a15b9171824241c77b20e0eb44e3b8\n\
       [1]   +1   4d8ced510cab21d23a5fd527dd122d7a3c12df33bc90a937c0a6b91fb6ea0992\n\
       [2]   +1   35f75fd1cfef0437bc7a4cae7387998f909fab1dfe6ced53d449c16090d8aa52\n\
       [3]   -1   73c027eac67a7b43af1a13427b2ad455451e4edfcaced8c2350b5d34adaa8020\n\
       [4]   +1   cbd441af056bf79c65a2154bc04ac2e0e40d7a2c0e77b80c27125f47d3d7cba3\n\
       [5]   +1   4e467bd5f3fc6767f12f4ffb918359da84f2a4de9ca44074488b8acf1e10262e\n\
       [6]   -1   db7f4ee8be8025dbffee11b434f179b3b0d0f3a1d7693a441f19653a65662ad3\n\
       [7]   -1   f235a9eb55315c9a197d069db9c75a01d99da934c5f80f9f175307fb6ac4d8fe\n\
       [8]   +1   e003d116f27c877f6de213cf4d03cce17b94aece7b2ec2f2b19367abf914bcc8\n\
       [9]   -1   6a59026cd21a32aaee21fe6522778b398464c6ea742ccd52285aa727c367d8f2\n\
      [10]   -1   2dca521da60bf0628caa3491065e32afc9da712feb38ff3886d1c8dda31193f8'
