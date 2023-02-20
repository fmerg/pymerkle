"""
pymerkle demo
"""

import sys
from math import log10
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
    ----------------------------------- PROOF ------------------------------------

    timestamp   : {timestamp} ({created_at})

    algorithm   : {algorithm}
    encoding    : {encoding}
    security    : {security}

    {path}

    offset      : {offset}

    commitment  : {commitment}

    -------------------------------- END OF PROOF --------------------------------
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


def display(obj):
    if isinstance(obj, MerkleTree):
        kw = {
            'algorithm': tree.algorithm,
            'encoding': tree.encoding.replace('_', '-'),
            'security': tree.security,
            'root': tree.get_root_hash().decode(),
            'length': tree.length,
            'size': tree.size,
            'height': tree.height,
        }
        sys.stdout.write(TREE_TEMPLATE.format(**kw))

    if isinstance(obj, MerkleProof):
        serialized = obj.serialize()
        metadata = serialized['metadata']
        encoding = metadata.pop('encoding').replace('_', '-')
        offset = serialized['body']['offset']
        path = serialized['body']['path']
        kw = {
            **metadata,
            'encoding': encoding.replace('_', '-'),
            'offset': offset,
            'path': strpath(obj.path, obj.encoding),
            'commitment': obj.commitment.decode()
        }
        sys.stdout.write(PROOF_TEMPLATE.format(**kw))


if __name__ == '__main__':

    tree = MerkleTree(algorithm='sha256', encoding='utf-8', security=True)

    # Populate tree with some entries
    for data in [b'foo', b'bar', b'baz', b'qux', b'quux']:
        tree.append_entry(data)

    display(tree)

    # Prove and verify inclusion of `bar`
    challenge = b'485904129bdda5d1b5fbc6bc4a82959ecfb9042db44dc08fe87e360b0a3f2501'
    proof = tree.prove_inclusion(challenge)

    display(proof)

    assert proof.verify()

    # Save current tree state
    state = tree.get_root_hash()

    # Append further entries
    for data in [b'corge', b'grault', b'garlpy']:
        tree.append_entry(data)

    print(tree)

    # Prove and verify saved state
    proof = tree.prove_consistency(challenge=state)
    display(proof)

    assert proof.verify()
    # import pdb; pdb.set_trace()
