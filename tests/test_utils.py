import pytest
from itertools import combinations
from pymerkle.utils import log2, decompose


numbers = [0]
logarithms = [0]
collections = [[]]

# 0 <= p <= 7
for logarithm in range(0, 8):

   # [0, 1, ..., p - 1]
    exponent_range = range(logarithm)

    for k in range(logarithm + 1):
        for _ in combinations(exponent_range, k):

            # [p, i_k, ..., i_1], i_1 < ... < i_k < p
            exponents = list(_) + [logarithm]

            # 2 ^ i_1 + ... + 2 ^ i_k + 2 ^ p
            number = sum(2 ** i for i in exponents)

            numbers += [number]
            logarithms += [logarithm]
            collections += [exponents]


@pytest.mark.parametrize('number, logarithm', zip(numbers, logarithms))
def test_log2(number, logarithm):
    assert log2(number) == logarithm


@pytest.mark.parametrize('number, exponents', zip(numbers, collections))
def test_decompose(number, exponents):
    assert decompose(number) == exponents
    assert log2(number) == (exponents[-1] if number > 0 else 0)
