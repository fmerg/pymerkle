import itertools
import pytest
from pymerkle import constants, InmemoryTree, SqliteTree as _SqliteTree


# Make init interface identical to that of InmemoryTree
class SqliteTree(_SqliteTree):

    def __init__(self, algorithm='sha256', security=True):
        super().__init__(':memory:', algorithm, security)

    @classmethod
    def init_from_entries(cls, entries, algorithm='sha256', security=True):
        tree = cls(algorithm, security)

        append = tree.append
        for entry in entries:
            append(entry)

        return tree


def pytest_addoption(parser):
    parser.addoption('--extended', action='store_true', default=False,
                     help='Test against all supported hash algorothms')
    parser.addoption('--backend', choices=['inmemory', 'sqlite'], default='inmemory',
                     help='Storage backend')
    parser.addoption('--maxsize', type=int, default=11,
                     help='Maximum size of tree fixtures')

option = None

def pytest_configure(config):
    global option
    option = config.option


def all_configs(option):
    algorithms = constants.ALGORITHMS if option.extended else ['sha256']

    return [{'algorithm': algorithm, 'security': security} for (security,
        algorithm) in itertools.product((True, False), algorithms)]


def resolve_backend(option):
    if option.backend == 'sqlite':
        return SqliteTree

    return InmemoryTree


def make_trees(default_config=False):
    configs = all_configs(option) if not default_config else [{'algorithm':
        'sha256', 'security': True}]
    MerkleTree = resolve_backend(option)

    return [MerkleTree.init_from_entries(
        [f'entry-{i}'.encode() for i in range(size)], **config)
                               for size in range(0, option.maxsize + 1)
                               for config in configs]


def tree_and_index(default_config=False):
    return [(tree, index) for tree in make_trees(default_config)
                          for index in range(1, tree.get_size() + 1)]


def tree_and_range(default_config=False):
    return [(tree, start, end) for tree in make_trees(default_config)
                               for start in range(0, tree.get_size())
                               for end in range(start + 1, tree.get_size())]
