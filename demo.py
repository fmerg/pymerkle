"""pymerkle demo"""

from pymerkle import MerkleTree


if __name__ == '__main__':

    tree = MerkleTree(algorithm='sha256', encoding='utf-8', security=True)

    # Populate tree with some records
    for data in [b'foo', b'bar', b'baz', b'qux', b'quux']:
        tree.encrypt(data)

    print(repr(tree))

    # Prove and verify encryption of `bar`
    challenge = b'485904129bdda5d1b5fbc6bc4a82959ecfb9042db44dc08fe87e360b0a3f2501'
    proof = tree.generate_audit_proof(challenge)
    print(proof)
    assert proof.verify()

    # Save current tree state
    state = tree.get_root_hash()

    # Append further leaves
    for data in [b'corge', b'grault', b'garlpy']:
        tree.encrypt(data)

    # Prove and verify saved state
    proof = tree.generate_consistency_proof(challenge=state)
    print(proof)
    assert proof.verify(state)
