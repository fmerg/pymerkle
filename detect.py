from pymerkle import *
import time

a = MerkleTree()
b = MerkleTree()
print('b', 'a')

t = b.inclusionTest(old_hash=a.rootHash(), sublength=a.length())
time.sleep(1)
print(0, 0, t)


b.update(str(1))
t = b.inclusionTest(old_hash=a.rootHash(), sublength=a.length())
time.sleep(1)
print(1, 0, t)

i = 1
power = 0
while i > 0:
    b.update(str(i + 1))
    a.update(str(i))
    if not not b.inclusionTest(
        old_hash=a.rootHash(),
        sublength=a.length()) or validateProof(
        target_hash=b.rootHash(),
        proof=b.consistencyProof(
            old_hash=a.rootHash(),
            sublength=a.length())):
        time.sleep(1)
        print(i + 1, i, power, 2**power)
        power += 1
    # if not b.inclusionTest(old_hash=a.rootHash(), sublength=a.length()):
    #     time.sleep(1)
    #     print(i + 1, i, power, 2**power)
    #     power += 1
    i += 1
