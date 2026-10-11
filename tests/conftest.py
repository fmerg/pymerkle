from pymerkle.hasher import ALGORITHMS
from tests.helpers import BACKENDS, make_configs, make_trees


DEFAULT_MAXSIZE = 11
DEFAULT_THRESHOLD = 2
DEFAULT_CAPACITY = 1024 ** 3


def pytest_addoption(parser):
    parser.addoption('--algorithm', default='sha256',
        choices=ALGORITHMS,
        help='Hash algorithm to be used')
    parser.addoption('--extended', action='store_true', default=False,
        help='Test against all supported hash algorithms')
    parser.addoption('--backend', choices=list(BACKENDS), default='inmemory',
        help='Storage backend')
    parser.addoption('--maxsize', type=int, default=DEFAULT_MAXSIZE,
        help='Maximum size of tree fixtures')
    parser.addoption('--threshold', type=int, metavar='WIDTH',
        default=DEFAULT_THRESHOLD,
        help='Subroot cache threshold')
    parser.addoption('--capacity', type=int, metavar='BYTES',
        default=DEFAULT_CAPACITY,
        help='Subroot cache capacity in bytes')


def pytest_configure(config):
    config.addinivalue_line('markers', 'default_config: run only against '
        'trees with the selected algorithm and security enabled')


def pytest_generate_tests(metafunc):
    """
    Parametrizes tests according to their argument names:

    - ``tree_class``: the selected backend
    - ``config``: the selected tree configurations
    - ``tree``: trees of every size up to the maximum, combined with
        ``index``, ``size`` or ``size1`` ranging from one to the tree size,
        or with ``start`` and ``end`` ranging over its leaf ranges
    """
    options = metafunc.config.option
    names = metafunc.fixturenames
    default_config = metafunc.definition.get_closest_marker(
        'default_config') is not None
    configs = make_configs(options, default_config)
    tree_class = BACKENDS[options.backend]

    if 'tree_class' in names:
        metafunc.parametrize('tree_class', [tree_class])

    if 'config' in names:
        metafunc.parametrize('config', configs)

    if 'tree' not in names:
        return

    trees = make_trees(tree_class, configs, options.maxsize)

    for name in ('index', 'size', 'size1'):
        if name in names:
            metafunc.parametrize(f'tree, {name}',
                [(tree, i) for tree in trees
                           for i in range(1, tree.get_size() + 1)])
            return

    if 'start' in names and 'end' in names:
        metafunc.parametrize('tree, start, end',
            [(tree, start, end) for tree in trees
                                for start in range(tree.get_size())
                                for end in range(start + 1,
                                    tree.get_size() + 1)])
        return

    metafunc.parametrize('tree', trees)
