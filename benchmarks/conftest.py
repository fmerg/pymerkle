import math
import os
from typing import Final

import pytest

from pymerkle import SqliteTree as MerkleTree
from pymerkle import constants

current_dir: str = os.path.dirname(os.path.abspath(__file__))

DEFAULT_DB: Final[str] = os.path.join(current_dir, 'merkle.db')
DEFAULT_SIZE: Final[int] = 10 ** 6
DEFAULT_INDEX: Final[int] = math.ceil(DEFAULT_SIZE / 2)
DEFAULT_ROUNDS: Final[int] = 100
DEFAULT_THRESHOLD: Final[int] = 128
DEFAULT_CAPACITY: Final[int] = 1024 ** 3


def pytest_addoption(parser):
    parser.addoption('--dbfile', type=str, default=DEFAULT_DB,
                     help='Database filepath')
    parser.addoption('--size', type=int, default=DEFAULT_SIZE,
                     help='Nr entries to consider')
    parser.addoption('--index', type=int, default=DEFAULT_INDEX,
                     help='Base index for proof operations')
    parser.addoption('--rounds', type=int, default=DEFAULT_ROUNDS,
                     help='Nr rounds per benchmark')
    parser.addoption('--algorithm', default='sha256',
                     choices=constants.ALGORITHMS,
                     help='Hash algorithm used by the tree')
    parser.addoption('--randomize', action='store_true', default=False,
                     help='Randomize function input per round')
    parser.addoption('--disable-optimizations', action='store_true', default=False,
                     help='Use unoptimized versions of core operations')
    parser.addoption('--disable-cache', action='store_true', default=False,
                     help='Disable subroot caching')
    parser.addoption('--threshold', type=int, metavar='WIDTH',
                     default=DEFAULT_THRESHOLD,
                     help='Subroot cache threshold')
    parser.addoption('--capacity', type=int, metavar='BYTES',
                     default=DEFAULT_CAPACITY,
                     help='Subroot cache capacity in bytes')


option = None


def pytest_configure(config) -> None:
    global option
    option = config.option
