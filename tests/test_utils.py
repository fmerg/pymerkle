import pytest
import itertools

from pymerkle import utils

logs = []
nums = []
pows = []

for p in list(range(0, 11)):    # 0 <= p <= 10

    indices = list(range(p))    # [0, 1, ... p-1]

    # 0 <= k <= p
    for k in range(p + 1):

        for comb in itertools.combinations(indices, k):
            comb = list(comb)

            # [i_1, ..., i_k, p], i_1 < ... < i_k < p
            comb.append(p)
            pows.append(comb)

            # 2 ^ i_1 + ... + 2 ^ i_k + 2 ^ p,   i_1 < ... < i_k < p,   0 <= p <= 10
            nums.append(sum((map(lambda x: 2 ** x, comb))))

            logs.append(p)


def test_log_2_exception():
    with pytest.raises(ValueError):
        utils.log_2(-1)


def test_log_2_zero_convention():
    assert utils.log_2(0) == 0


@pytest.mark.parametrize('num, expected', zip(nums, logs))
def test_log_2(num, expected):
    assert utils.log_2(num) == expected


def test_decompose_zero_convention():
    assert utils.decompose(0) == []


def test_decompose_negative_convention():
    assert utils.decompose(-1) == []


@pytest.mark.parametrize('num, powers', zip(nums, pows))
def test_decompose(num, powers):
    assert utils.decompose(num) == list(reversed(powers))
