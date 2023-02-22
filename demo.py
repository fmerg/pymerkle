"""
pymerkle demo
"""

import sys
from math import log10
from datetime import datetime
from pymerkle import MerkleTree, MerkleProof


TREE_TEMPLATE = """
    algorithm : {algorithm}
    encoding  : {encoding}
    security  : {security}
    root      : {root}
    length    : {length}
    size      : {size}
    height    : {height}
"""


PROOF_TEMPLATE = """
    algorithm   : {algorithm}
    encoding    : {encoding}
    security    : {security}
    timestamp   : {timestamp} ({created_at})
    offset      : {offset}
    commitment  : {commitment}

    {path}

"""


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
            'value': curr[1].decode(encoding)
        }
        pairs += [template.format(**kw)]

    return ''.join(pairs)


def template(obj):
    if isinstance(obj, MerkleTree):
        kw = {
            'algorithm': tree.algorithm,
            'encoding': tree.encoding.replace('_', '-'),
            'security': tree.security,
            'root': tree.get_root().decode(),
            'length': tree.length,
            'size': tree.size,
            'height': tree.height,
        }
        return TREE_TEMPLATE.format(**kw)

    if isinstance(obj, MerkleProof):
        serialized = obj.serialize()
        metadata = serialized['metadata']
        timestamp = metadata['timestamp']
        encoding = metadata.pop('encoding').replace('_', '-')
        offset = serialized['body']['offset']
        path = serialized['body']['path']
        kw = {
            **metadata,
            'created_at': datetime.utcfromtimestamp(timestamp).strftime(
                '%Y-%m-%d %H:%M:%S'),
            'encoding': encoding.replace('_', '-'),
            'offset': offset,
            'path': strpath(obj.path, obj.encoding),
            'commitment': obj.commitment.decode()
        }
        return PROOF_TEMPLATE.format(**kw)


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


if __name__ == '__main__':
    tree = MerkleTree(algorithm='sha256', encoding='utf-8', security=True)

    # Populate tree with some entries
    for data in [b'foo', b'bar', b'baz', b'qux', b'quux']:
        tree.append_entry(data)

    sys.stdout.write(template(tree))
    sys.stdout.write(structure(tree))

    # Prove and verify inclusion of `bar`
    challenge = b'485904129bdda5d1b5fbc6bc4a82959ecfb9042db44dc08fe87e360b0a3f2501'
    proof = tree.prove_inclusion(challenge)
    sys.stdout.write(template(proof))

    assert proof.verify()

    # Save current tree state
    state = tree.get_root()

    # Append further entries
    for data in [b'corge', b'grault', b'garlpy']:
        tree.append_entry(data)

    sys.stdout.write(template(tree))
    sys.stdout.write(structure(tree))

    # Prove and verify saved state
    proof = tree.prove_consistency(challenge=state)
    sys.stdout.write(template(proof))

    assert proof.verify()
