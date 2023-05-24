import itertools
import pytest
from pymerkle import constants, InmemoryTree as MerkleTree


def pytest_addoption(parser):
    parser.addoption('--extended', action='store_true', default=False,
                     help='Test against all supported encoding types')

option = None

def pytest_configure(config):
    global option
    option = config.option


def all_configs(option):
    algorithms = constants.ALGORITHMS
    encodings = constants.ENCODINGS if option.extended else \
        ['utf-8', 'utf-16', 'utf-32']

    for (security, algorithm, encoding) in itertools.product(
        (True, False),
        algorithms,
        encodings,
    ):
        yield {'security': security, 'algorithm': algorithm,
               'encoding': encoding}


def tree_and_index(maxsize=7, default_config=False):
    fixtures = []
    configs = all_configs(option) if not default_config else [{'algorithm':
        'sha256', 'encoding': 'utf-8', 'security': True}]

    for config in configs:
        for size in range(0, maxsize + 1):
            entries = [f'{i}-th entry' for i in range(size)]
            tree = MerkleTree.init_from_entries(*entries, **config)

            for index in range(1, size + 1):
                fixtures += [(tree, index)]

    return fixtures
