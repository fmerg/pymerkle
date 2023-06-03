import itertools
import pytest
from pymerkle import constants, InmemoryTree, SqliteTree as _SqliteTree


# Make init interface identical to that of InMemoryTree
class SqliteTree(_SqliteTree):

    def __init__(self, algorithm='sha256', security=True):
        super().__init__(':memory:', algorithm, security)


def pytest_addoption(parser):
    parser.addoption('--extended', action='store_true', default=False,
                     help='Test against all supported hash algorothms')
    parser.addoption('--backend', choices=['inmemory', 'sqlite'], default='inmemory',
                     help='Tree backend storage')

option = None

def pytest_configure(config):
    global option
    option = config.option


def all_configs(option):
    algorithms = constants.ALGORITHMS if option.extended else ['sha256']

    for (security, algorithm) in itertools.product(
        (True, False),
        algorithms,
    ):
        yield {'security': security, 'algorithm': algorithm}


def resolve_backend(option):
    if option.backend == 'sqlite':
        return SqliteTree

    return InmemoryTree


def tree_and_index(maxsize=7, default_config=False):
    fixtures = []
    configs = all_configs(option) if not default_config else [{'algorithm':
        'sha256', 'security': True}]

    MerkleTree = resolve_backend(option)

    for config in configs:
        for size in range(0, maxsize + 1):
            entries = [f'{i}-th entry'.encode() for i in range(size)]
            tree = MerkleTree.init_from_entries(*entries, **config)

            for index in range(1, size + 1):
                fixtures += [(tree, index)]

    return fixtures
