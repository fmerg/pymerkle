import itertools
import pytest
from pymerkle import constants, InmemoryTree, SqliteTree as _SqliteTree


DEFAULT_MAXSIZE = 11
DEFAULT_THRESHOLD = 2
DEFAULT_CAPACITY = 1024 ** 3


class SqliteTree(_SqliteTree):
    """
    Make init interface identical to that of InmemoryTree so that it can be
    used interchangeably
    """

    def __init__(self, algorithm='sha256', **opts):
        super().__init__(':memory:', algorithm, **opts)

    @classmethod
    def init_from_entries(cls, entries, algorithm='sha256', **opts):
        tree = cls(algorithm, **opts)
        tree.append_entries(entries, chunksize=2)

        return tree


def pytest_addoption(parser):
    parser.addoption('--algorithm', default='sha256',
        choices=constants.ALGORITHMS,
        help='Hash algorithm to be used')
    parser.addoption('--extended', action='store_true', default=False,
        help='Test against all supported hash algorothms')
    parser.addoption('--backend', choices=['inmemory', 'sqlite'], default='inmemory',
        help='Storage backend')
    parser.addoption('--maxsize', type=int, default=DEFAULT_MAXSIZE,
        help='Maximum size of tree fixtures')
    parser.addoption('--threshold', type=int, metavar='WIDTH',
        default=DEFAULT_THRESHOLD,
        help='Subroot cache threshold')
    parser.addoption('--capacity', type=int, metavar='BYTES',
        default=DEFAULT_CAPACITY,
        help='Subroot cache capacity in bytes')

option = None

def pytest_configure(config):
    global option
    option = config.option


def all_configs(option):
    algorithms = constants.ALGORITHMS if option.extended else [option.algorithm]

    configs = []
    for (disable_security, algorithm) in itertools.product((True, False), algorithms):
        config = {'algorithm': option.algorithm,
                  'disable_security': disable_security,
                  'threshold': option.threshold,
                  'capacity': option.capacity}
        configs += [config]

    return configs


def resolve_backend(option):
    if option.backend == 'sqlite':
        return SqliteTree

    return InmemoryTree


def make_trees(default_config=False):
    configs = all_configs(option) if not default_config else [{'algorithm':
        option.algorithm, 'disable_security': False}]
    MerkleTree = resolve_backend(option)

    return [MerkleTree.init_from_entries(
        [f'entry-{i}'.encode() for i in range(size)], **config)
                               for size in range(0, option.maxsize + 1)
                               for config in configs]


def tree_and_index(default_config=False):
    return [(tree, index) for tree in make_trees(default_config)
                          for index in range(1, tree.get_size() + 1)]


def tree_and_range(default_config=False):
    return [(tree, start, limit) for tree in make_trees(default_config)
                                 for start in range(0, tree.get_size())
                                 for limit in range(start + 1, tree.get_size())]
