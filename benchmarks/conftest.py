import os
import math
import pytest

from pymerkle import SqliteTree as MerkleTree

current_dir = os.path.dirname(os.path.abspath(__file__))

DEFAULT_DB = os.path.join(current_dir, 'merkle.db')
DEFAULT_SIZE = 10 ** 7
DEFAULT_INDEX = math.ceil(DEFAULT_SIZE / 2)
DEFAULT_ROUNDS = 100


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
                     help='Hash algorithm used by the tree')
    parser.addoption('--randomize', action='store_true', default=False,
                     help='Randomize function input per round')
    parser.addoption('--disable-optimizations', action='store_true', default=False,
                     help='Use unoptimized versions of core operations')
    parser.addoption('--disable-cache', action='store_true', default=False,
                     help='Disable subroot caching')

option = None

def pytest_configure(config):
    global option
    option = config.option
