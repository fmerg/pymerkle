"""
pymerkle demo
"""

import sys
from math import log10
from datetime import datetime
from pymerkle import MerkleTree, verify_inclusion, verify_consistency


def expand(node, encoding, indent, trim=None, level=0, ignored=None):
    ignored = ignored or []

    if level == 0:
        out = 2 * '\n' + ' └─' if not node.parent else ''
    else:
        out = (indent + 1) * ' '

    col = 1
    while col < level:
        out += ' │' if col not in ignored else 2 * ' '
        out += indent * ' '
        col += 1

    if node.is_left_child():
        out += ' ├──'

    if node.is_right_child():
        out += ' └──'
        ignored += [level]

    checksum = node.value.decode(encoding)
    out += (checksum[:trim] + '...') if trim else checksum
    out += '\n'

    if node.is_leaf():
        return out

    recursion = (encoding, indent, trim, level + 1, ignored[:])

    out += expand(node.left, *recursion)
    out += expand(node.right, *recursion)

    return out


def structure(tree, indent=2, trim=8):
    if not tree:
        return '\n └─[None]\n'

    return expand(tree.root, tree.encoding, indent, trim) + '\n'


def dimensions(tree):
    return '\n nr leaves: %s' % tree.get_size()


def order_of_magnitude(num):
    return int(log10(num)) if num != 0 else 0


def strpath(rule, path, encoding):
    template = '\n{left}[{index}]{middle}{bit}{right}{value}'
    pairs = []
    for index, (bit, value) in enumerate(zip(rule, path)):
        kw = {
            'left': (7 - order_of_magnitude(index)) * ' ',
            'index': index,
            'middle': 3 * ' ',
            'bit': bit,
            'right': 3 * ' ',
            'value': value,
        }
        pairs += [template.format(**kw)]

    return ''.join(pairs)


def display(proof):
    template = """
    algorithm   : {algorithm}
    encoding    : {encoding}
    security    : {security}
    size        : {size}
    rule        : {rule}
    subset      : {subset}
    {path}\n\n"""

    serialized = proof.serialize()

    metadata = serialized['metadata']
    size = serialized['size']
    rule = serialized['rule']
    subset = serialized['subset']
    path = serialized['path']

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

    sys.stdout.write(dimensions(tree))
    sys.stdout.write(structure(tree))

    # Prove and verify inclusion of `bar`
    proof = tree.prove_inclusion(2)
    sys.stdout.write(display(proof))

    target = tree.get_state()
    base = tree.get_leaf(2)
    verify_inclusion(base, target, proof)

    # Save current state and append further entries
    size1 = tree.get_size()
    state1 = tree.get_state()
    for data in [b'corge', b'grault', b'garlpy']:
        tree.append_leaf(data)

    sys.stdout.write(dimensions(tree))
    sys.stdout.write(structure(tree))

    # Prove and verify previous state
    size2 = tree.get_size()
    proof = tree.prove_consistency(size1, size2)
    sys.stdout.write(display(proof))

    state2 = tree.get_state()
    verify_consistency(state1, state2, proof)
