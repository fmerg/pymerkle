"""
Run tree operations for profiling purposes
"""

import os
import sys
import argparse
from random import randint

from pymerkle import SqliteTree as MerkleTree
from pymerkle import constants

current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)

DEFAULT_DB = os.path.join(parent_dir, 'benchmarks', 'merkle.db')
DB_SIZE = 10 ** 6
DEFAULT_ROUNDS = 1
DEFAULT_THRESHOLD = 128
DEFAULT_CAPACITY = 1024 ** 3


def parse_cli_args():
    config = {'prog': sys.argv[0], 'usage': 'python %s' % sys.argv[0],
              'description': __doc__, 'epilog': '\n',
              'formatter_class': argparse.ArgumentDefaultsHelpFormatter}
    parser = argparse.ArgumentParser(**config)

    parser.add_argument('--dbfile', type=str, default=DEFAULT_DB,
        help='Database filepath')
    parser.add_argument('--algorithm', choices=constants.ALGORITHMS,
        default='sha256', help='Hashing algorithm')
    parser.add_argument('--rounds', type=int, default=DEFAULT_ROUNDS,
        help='Nr rounds')
    parser.add_argument('--randomize', action='store_true', default=False,
        help='Randomize function input per round')
    parser.add_argument('--disable-optimizations', action='store_true', default=False,
        help='Use unoptimized versions of core functionalities')
    parser.add_argument('--disable-cache', action='store_true', default=False,
        help='Disable subroot caching')
    parser.add_argument('--threshold', type=int, metavar='WIDTH',
        default=DEFAULT_THRESHOLD, 
        help='Subroot cache threshold')
    parser.add_argument('--capacity', type=int, metavar='BYTES',
        default=DEFAULT_CAPACITY,
        help='Subroot cache capacity in bytes')

    operation = parser.add_subparsers(dest='operation')

    root = operation.add_parser('root',
        help='Run `_get_root`')
    root.add_argument('--start', type=int, default=0,
        help='Starting position')
    root.add_argument('--limit', type=int, default=DB_SIZE,
        help='Final position')

    state = operation.add_parser('state',
        help='Run `get_state`')
    state.add_argument('--size', type=int, default=DB_SIZE,
        help='Nr entries to consider')

    inclusion = operation.add_parser('inclusion',
        help='Run `prove_inclusion`')
    inclusion.add_argument('--index', type=int, required=True,
        help='Leaf index')
    inclusion.add_argument('--size', type=int, default=DB_SIZE,
        help='Nr entries to consider')

    consistency = operation.add_parser('consistency',
        help='Run `prove_consistency`')
    consistency.add_argument('--size1', type=int, required=True,
        help='Size of prior state')
    consistency.add_argument('--size2', type=int, default=DB_SIZE,
        help='Size of later state')

    return parser.parse_args()


if __name__ == '__main__':
    cli = parse_cli_args()

    opts = {'disable_optimizations': cli.disable_optimizations,
            'disable_cache': cli.disable_cache,
            'threshold': cli.threshold,
            'capacity': cli.capacity}

    tree = MerkleTree(cli.dbfile, algorithm=cli.algorithm, **opts)

    match cli.operation:
        case 'root':
            func = tree._get_root

            def get_args():
                return (cli.start, cli.limit)

            if cli.randomize:
                def get_args():
                    start = randint(0, cli.limit - 2)
                    limit = randint(start + 1, cli.limit)

                    return (start, limit)

        case 'state':
            func = tree.get_state

            def get_args():
                return (cli.size,)

            if cli.randomize:
                def get_args():
                    size = randint(1, cli.size)

                    return (size,)

        case 'inclusion':
            func = tree.prove_inclusion

            def get_args():
                return (cli.index, cli.size)

            if cli.randomize:
                def get_args():
                    size = cli.size
                    index = randint(1, size)

                    return (index, size)

        case 'consistency':
            func = tree.prove_consistency

            def get_args():
                return (cli.size1, cli.size2)

            if cli.randomize:
                def get_args():
                    size2 = cli.size2
                    size1 = randint(1, size2)

                    return (size1, size2)

    count = 0
    while count < cli.rounds:
        args = get_args()
        print('round %d:' % count, args)
        func(*args)
        count += 1

    print("\033[92m {}\033[00m".format(tree.get_cache_info()))
