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


def backend_id(tree_class):
    return next(name for (name, cls) in BACKENDS.items() if cls is tree_class)


def config_id(config):
    mode = 'insecure' if config['disable_security'] else 'secure'

    return f"{config['algorithm']}-{mode}"


def tree_id(tree):
    """
    Test id identifying the backend, configuration and size of a tree,
    e.g., ``sqlite-sha256-secure-size5``.
    """
    mode = 'secure' if tree.security else 'insecure'

    return f'{backend_id(type(tree))}-{tree.algorithm}-{mode}-' \
        f'size{tree.get_size()}'


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
