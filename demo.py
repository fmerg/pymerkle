"""
pymerkle demo
"""

import sys
from math import log10
from pymerkle import MerkleTree, verify_inclusion, verify_consistency


def order_of_magnitude(num):
    return int(log10(num)) if num != 0 else 0


def strpath(rule, path, encoding):
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


def strproof(proof):
    template = """
    algorithm   : {algorithm}
    encoding    : {encoding}
    security    : {security}
    size        : {size}
    rule        : {rule}
    subset      : {subset}
    {path}\n\n"""

    data = proof.serialize()
    metadata = data['metadata']
    size = data['size']
    rule = data['rule']
    subset = data['subset']
    path = data['path']

    encoding = metadata.pop('encoding').replace('_', '')
    path = strpath(rule, path, encoding)

    kw = {**metadata, 'encoding': encoding, 'size': size, 'rule': rule,
          'subset': subset, 'path': path}
    return template.format(**kw)


if __name__ == '__main__':
    tree = MerkleTree(algorithm='sha256', encoding='utf-8', security=True)

    # Populate tree with some entries
    for data in [b'foo', b'bar', b'baz', b'qux', b'quux']:
        tree.append_leaf(data)

    sys.stdout.write('\n nr leaves: %d' % tree.get_size())
    sys.stdout.write(str(tree))

    # Prove and verify inclusion of `bar`
    proof = tree.prove_inclusion(2)
    sys.stdout.write(strproof(proof))

    target = tree.get_state()
    base = tree.get_leaf(2)
    verify_inclusion(base, target, proof)

    # Save current state and append further entries
    size1 = tree.get_size()
    state1 = tree.get_state()
    for data in [b'corge', b'grault', b'garlpy']:
        tree.append_leaf(data)

    sys.stdout.write('\n nr leaves: %d' % tree.get_size())
    sys.stdout.write(str(tree))

    # Prove and verify previous state
    size2 = tree.get_size()
    proof = tree.prove_consistency(size1, size2)
    sys.stdout.write(strproof(proof))

    state2 = tree.get_state()
    verify_consistency(state1, state2, proof)
