from pymerkle import *
import time

a = MerkleTree()
b = MerkleTree()
print('b >= a')

t = b.inclusionTest(old_hash=a.rootHash(), sublength=a.length())
v = validateProof(target_hash=b.rootHash(),proof=b.consistencyProof(
    old_hash=a.rootHash(),sublength=a.length()))
time.sleep(1)
print(t, v, 0, 0)


b.update(str(1))
t = b.inclusionTest(old_hash=a.rootHash(), sublength=a.length())
v = validateProof(target_hash=b.rootHash(),proof=b.consistencyProof(old_hash=a.rootHash(),sublength=a.length()))
time.sleep(1)
print(t, v, 1, 0)

i = 1
power = 0
while i > 0:
    b.update(str(i + 1))
    a.update(str(i))
    t = b.inclusionTest(
        old_hash=a.rootHash(),
        sublength=a.length())
    v = validateProof(
        target_hash=b.rootHash(),
        proof=b.consistencyProof(
            old_hash=a.rootHash(),
            sublength=a.length()))
    if not t or not v:
        time.sleep(1)
        print(t, v, i + 1, i, power, 2**power)
        power += 1
    i += 1
