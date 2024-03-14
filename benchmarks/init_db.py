"""
Create tree sqlite database for benchmarking. WARNING: Unless otherwise specified,
the database file will be overwritten if it already exists.
"""

import os
import sys
import argparse
import time

from pymerkle import SqliteTree, constants

current_dir = os.path.dirname(os.path.abspath(__file__))

DEFAULT_DB = os.path.join(current_dir, 'merkle.db')
DEFAULT_ALGORITHM = 'sha256'
DEFAULT_SIZE = 10 ** 8
DEFAULT_BATCHSIZE = 10 ** 7


def parse_cli_args():
    config = {'prog': sys.argv[0], 'usage': 'python %s' % sys.argv[0],
              'description': __doc__, 'epilog': '\n',
              'formatter_class': argparse.ArgumentDefaultsHelpFormatter}
    parser = argparse.ArgumentParser(**config)

    parser.add_argument('--dbfile', type=str, default=DEFAULT_DB,
        help='Database filepath')
    parser.add_argument('--algorithm', choices=constants.ALGORITHMS,
        default=DEFAULT_ALGORITHM, help='Hashing algorithm')
    parser.add_argument('--disable-security', action='store_true', default=False,
        help='Disable resistance against 2nd-preimage attack')
    parser.add_argument('--size', type=int, default=DEFAULT_SIZE,
        help='Nr entries to append in total')
    parser.add_argument('--batchsize', type=int, default=DEFAULT_BATCHSIZE,
        help='Nr entries to append per bulk insertion')
    parser.add_argument('--preserve-database', action='store_true', default=False,
        help='Append without overwriting if already existent')

    return parser.parse_args()


if __name__ == '__main__':
    args = parse_cli_args()

    batchsize = args.batchsize
    size = args.size
    if batchsize > size:
        sys.stdout.write("[-] Batchsize exceeds size\n")
        sys.exit(1)

    if not args.preserve_database:
        try:
            os.remove(args.dbfile)
        except OSError:
            pass

    opts = {'algorithm': args.algorithm,
            'disable_security': args.disable_security}

    with SqliteTree(args.dbfile, **opts) as tree:
        offset = 0
        count = 1
        append_entries = tree.append_entries
        chunksize = min(100_000, batchsize)
        start_time = time.time()
        while offset < size:
            limit = offset + batchsize + 1
            if limit > size + 1:
                limit = size + 1

            print(f"\nCreating {batchsize} entries...")
            entries = [f'entry-{i}'.encode('utf-8') for i in range(offset + 1,
                limit)]

            index = append_entries(entries, chunksize)
            assert index == limit - 1

            currsize = tree.get_size()
            print("\033[92m {}\033[00m".format(f"Appended batch {count}"))
            print("\033[92m {}\033[00m".format(f"Current size: {currsize}"))

            count += 1
            offset += batchsize

        end_time = time.time()
        elapsed_time = end_time - start_time

        assert currsize == args.size

        print(f"\nDatabase at {args.dbfile}\n")
        print("\nTime elapsed (sec):", elapsed_time)
