"""
Helpers shared by the test modules.
"""

import itertools

from pymerkle import InmemoryTree, SqliteTree as _SqliteTree
from pymerkle.hasher import ALGORITHMS


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


BACKENDS = {'inmemory': InmemoryTree, 'sqlite': SqliteTree}


def make_configs(options, default_config=False):
    """
    Tree configurations selected by the command line options; only the
    selected algorithm with security enabled if *default_config* is set.
    """
    if default_config:
        return [{'algorithm': options.algorithm, 'disable_security': False}]

    algorithms = ALGORITHMS if options.extended else [options.algorithm]

    return [{'algorithm': algorithm,
             'disable_security': disable_security,
             'threshold': options.threshold,
             'capacity': options.capacity}
            for (disable_security, algorithm) in itertools.product(
                (True, False), algorithms)]


def make_trees(tree_class, configs, maxsize):
    """
    Trees of every size up to *maxsize* for each of the provided
    configurations.
    """
    return [tree_class.init_from_entries(
        [f'entry-{i}'.encode() for i in range(size)], **config)
            for size in range(0, maxsize + 1)
            for config in configs]
