"""
pymerkle demo
"""

import sys
import argparse
from math import log10
from pymerkle import (
    constants,
    InmemoryTree,
    SqliteTree as _SqliteTree,
    verify_inclusion,
    verify_consistency
)


# Make init interface identical to that of InmemoryTree
class SqliteTree(_SqliteTree):

    def __init__(self, algorithm='sha256', security=True):
        super().__init__(':memory:', algorithm, security)


def parse_cli_args():
    config = {'prog': sys.argv[0], 'usage': 'python %s' % sys.argv[0],
              'description': __doc__, 'epilog': '\n',
              'formatter_class': argparse.ArgumentDefaultsHelpFormatter}

    parser = argparse.ArgumentParser(**config)

    parser.add_argument('--backend', choices=['inmemory', 'sqlite'],
            default='inmemory', help='Storage backend')
    parser.add_argument('--algorithm', choices=constants.ALGORITHMS,
            default='sha256', help='Hashing algorithm')
    parser.add_argument('--no-security', action='store_true',
            default=False, help='Disable resistance against second-preimage attack')

    return parser.parse_args()


def order_of_magnitude(num):
    return int(log10(num)) if not num == 0 else 0


def strpath(rule, path):
    s2 = 3 * ' '
    s3 = 3 * ' '
    template = '\n{s1}[{index}]{s2}{bit}{s3}{value}'

    pairs = []
    for index, (bit, value) in enumerate(zip(rule, path)):
        s1 = (7 - order_of_magnitude(index)) * ' '
        kw = {'s1': s1, 'index': index, 's2': s2, 'bit': bit, 's3': s3,
              'value': value}
        pairs += [template.format(**kw)]

    return ''.join(pairs)


def strtree(tree):
    if isinstance(tree, SqliteTree):
        entries = [tree.get_entry(index) for index in range(1, tree.get_size()
            + 1)]
        tree = InmemoryTree.init_from_entries(entries)

    return str(tree)


def strproof(proof):
    template = """
    algorithm   : {algorithm}
    security    : {security}
    size        : {size}
    rule        : {rule}
    subset      : {subset}
    {path}\n\n"""

    data = proof.serialize()
    metadata = data['metadata']
    rule = data['rule']
    subset = data['subset']
    path = data['path']

    path = strpath(rule, path)

    kw = {**metadata, 'rule': rule, 'subset': subset, 'path': path}
    return template.format(**kw)


if __name__ == '__main__':
    args = parse_cli_args()

    MerkleTree = { 'inmemory': InmemoryTree, 'sqlite': SqliteTree }[
        args.backend]

    config = {'algorithm': args.algorithm, 'security': not args.no_security}
    tree = MerkleTree(**config)

    # Populate tree with some entries
    for entry in [b'foo', b'bar', b'baz', b'qux', b'quux']:
        tree.append(entry)

    sys.stdout.write('\n nr leaves: %d' % tree.get_size())
    sys.stdout.write(strtree(tree))

    # Prove and verify inclusion of `bar`
    proof = tree.prove_inclusion(2)
    sys.stdout.write(strproof(proof))

    target = tree.get_state()
    base = tree.get_leaf(2)
    verify_inclusion(base, target, proof)

    # Save current state and append further entries
    lsize = tree.get_size()
    state1 = tree.get_state()
    for entry in [b'corge', b'grault', b'garlpy']:
        tree.append(entry)

    sys.stdout.write('\n nr leaves: %d' % tree.get_size())
    sys.stdout.write(strtree(tree))

    # Prove and verify previous state
    rsize = tree.get_size()
    proof = tree.prove_consistency(lsize, rsize)
    sys.stdout.write(strproof(proof))

    state2 = tree.get_state()
    verify_consistency(state1, state2, proof)
