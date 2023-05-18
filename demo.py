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

    return expand(tree.root_node, tree.encoding, indent, trim) + '\n'


def dimensions(tree):
    return '\n leaves: %s, height: %d' % (tree.length, tree.height)


def order_of_magnitude(num):
    return int(log10(num)) if num != 0 else 0


def get_signed(num):
    return f'{"+" if num >= 0 else ""}{num}'


def strpath(path, encoding):
    template = '\n{left}[{index}]{middle}{sign}{right}{value}'

    pairs = []
    for index, curr in enumerate(path):
        kw = {
            'left': (7 - order_of_magnitude(index)) * ' ',
            'index': index,
            'middle': 3 * ' ',
            'sign': get_signed(curr[0]),
            'right': 3 * ' ',
            'value': curr[1]
        }
        pairs += [template.format(**kw)]

    return ''.join(pairs)


def display(proof):
    template = """
    algorithm   : {algorithm}
    encoding    : {encoding}
    security    : {security}
    offset      : {offset}
    {path}\n\n"""

    serialized = proof.serialize()

    metadata = serialized['metadata']
    path = serialized['path']
    offset = serialized['offset']

    encoding = metadata.pop('encoding').replace('_', '')
    offset = offset
    path = strpath(path, encoding)

    kw = {**metadata, 'encoding': encoding, 'offset': offset, 'path': path}
    return template.format(**kw)


if __name__ == '__main__':
    tree = MerkleTree(algorithm='sha256', encoding='utf-8', security=True)

    # Populate tree with some entries
    for data in [b'foo', b'bar', b'baz', b'qux', b'quux']:
        tree.append_entry(data)

    sys.stdout.write(dimensions(tree))
    sys.stdout.write(structure(tree))

    # Prove and verify inclusion of `bar`
    proof = tree.prove_inclusion(b'bar')
    sys.stdout.write(display(proof))

    verify_inclusion(b'bar', tree.root, proof)

    # Save current tree state
    sublength = tree.length
    subroot = tree.root

    # Append further entries
    for data in [b'corge', b'grault', b'garlpy']:
        tree.append_entry(data)

    sys.stdout.write(dimensions(tree))
    sys.stdout.write(structure(tree))

    # Prove and verify previous state
    proof = tree.prove_consistency(sublength, subroot)
    sys.stdout.write(display(proof))

    verify_consistency(subroot, tree.root, proof)
