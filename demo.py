"""pymerkle demo"""

from pymerkle import MerkleTree, MerkleVerifier


if __name__ == '__main__':

    tree = MerkleTree(hash_type='sha256', encoding='utf-8', raw_bytes=True,
            security=True)

    for i in range(7):
        tree.encryptRecord('%d-th record' % i)

    print(repr(tree))

    challenge = {
        'checksum': '45c44059cf0f5a447933f57d851a6024ac78b44a41603738f563bcbf83f35d20'
    }

    proof = tree._generate_proof(challenge)
    print(proof)

    assert MerkleVerifier().verify_proof(proof)
