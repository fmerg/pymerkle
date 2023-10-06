"""
Create tree sqlite database for benchmarking. WARNING: Unless otherwise specified,
the database file will be overwritten if it already exists.
"""

import argparse
import os
import sys
import time
from typing import Any, Final

from pymerkle import SqliteTree, constants

current_dir: str = os.path.dirname(os.path.abspath(path=__file__))

DEFAULT_DB: Final[str] = os.path.join(current_dir, 'merkle.db')
DEFAULT_ALGORITHM: Final[str] = 'sha256'
DEFAULT_SIZE: Final[int] = 10 ** 8
DEFAULT_BATCHSIZE: Final[int] = 10 ** 7


def parse_cli_args() -> argparse.Namespace:
    config: dict[str, Any] = {'prog': sys.argv[0], 'usage': 'python %s' % sys.argv[0],
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
    args: argparse.Namespace = parse_cli_args()

    batchsize = int(args.batchsize)
    size = args.size
    if batchsize > size:
        sys.stdout.write("[-] Batchsize exceeds size\n")
        sys.exit(1)

    if not args.preserve_database:
        try:
            os.remove(path=args.dbfile)
        except OSError:
            pass

    opts: dict[str, Any] = {'algorithm': args.algorithm,
                            'disable_security': args.disable_security}

    with SqliteTree(dbfile=args.dbfile, **opts) as tree:
        offset: int = 0
        count: int = 1
        append_entries = tree.append_entries
        chunksize: int = min(100_000, batchsize)
        start_time: float = time.time()
        currsize: int = 0
        while offset < size:
            limit: int = offset + batchsize + 1
            if limit > size + 1:
                limit = size + 1

            print(f"\nCreating {batchsize} entries...")
            entries: list[bytes] = [f'entry-{i}'.encode(encoding='utf-8') for i in range(offset + 1,
                                                                                         limit)]

            index: int = append_entries(
                entries=entries, chunksize=chunksize)  # type: ignore
            assert index == limit - 1

            currsize = tree.get_size()
            print("\033[92m {}\033[00m".format(f"Appended batch {count}"))
            print("\033[92m {}\033[00m".format(f"Current size: {currsize}"))

            count += 1
            offset += batchsize

        end_time: float = time.time()
        elapsed_time: float = end_time - start_time

        assert currsize == args.size

        print(f"\nDatabase at {args.dbfile}\n")
        print("\nTime elapsed (sec):", elapsed_time)
