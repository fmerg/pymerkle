from pymerkle.tree import MerkleTree
from pymerkle.validations import validateProof
import math

ROUNDS            = 100
ITERATIONS        =  12
WARMUP_ROUNDS     =  10
LENGTH            = 100
FILE_PATH         = '../pymerkle/tests/logs/short_APACHE_log'
LOG_FILE_PATH     = '../pymerkle/tests/logs/short_APACHE_log'
RECORD            = 'oculusnonviditnecaurisaudivit'
ENCODING          = 'utf-8'
HASH_TYPE         = 'sha256'

TREE              = None
TARGET_HASH       = None
SUBLENGTH         = None
oldhash          = None
PROOF             = None
VALIDATION        = None


def test_tree_generation(benchmark):

    def generate_MerkleTree(*records):
        global TREE
        TREE = MerkleTree(*records, hash_type=HASH_TYPE, encoding=ENCODING)

    benchmark.pedantic(
        generate_MerkleTree,
        args=(['%d-th record' % _ for _ in range(LENGTH)]),
        rounds=ROUNDS,
        iterations=ITERATIONS,
        warmup_rounds=WARMUP_ROUNDS
    )


def test_log_encryption(benchmark):

    benchmark.pedantic(
        TREE.encryptFilePerLog,
        args=(LOG_FILE_PATH,),
        rounds=ROUNDS,
        iterations=ITERATIONS,
        warmup_rounds=WARMUP_ROUNDS
    )


def test_audit_proof_generation(benchmark):

    benchmark.pedantic(
        TREE.auditProof,
        args=(math.floor(TREE.length/2),),
        rounds=ROUNDS,
        iterations=ITERATIONS,
        warmup_rounds=WARMUP_ROUNDS
    )


def test_file_encryption(benchmark):

    benchmark.pedantic(
        TREE.encryptFileContent,
        args=(FILE_PATH,),
        rounds=ROUNDS,
        iterations=ITERATIONS,
        warmup_rounds=WARMUP_ROUNDS
    )


def test_record_encryption(benchmark):

    benchmark.pedantic(
        TREE.encryptRecord,
        args=(RECORD,),
        rounds=ROUNDS,
        iterations=ITERATIONS,
        warmup_rounds=WARMUP_ROUNDS
    )


def test_consistency_proof_generation(benchmark):

    global oldhash
    global SUBLENGTH
    oldhash  = TREE.rootHash
    SUBLENGTH = TREE.length
    TREE.encryptFilePerLog(LOG_FILE_PATH,),

    def generate_consistency_proof(oldhash, sublength):
        global PROOF
        PROOF = TREE.consistencyProof(oldhash=oldhash, sublength=sublength)

    benchmark.pedantic(
        generate_consistency_proof,
        kwargs={'oldhash': oldhash, 'sublength': SUBLENGTH},
        rounds=ROUNDS,
        iterations=ITERATIONS,
        warmup_rounds=WARMUP_ROUNDS
    )

    assert validateProof(target_hash=TREE.rootHash, proof=PROOF)


def test_proof_validation(benchmark):

    def validate_proof():
        global VALIDATION
        VALIDATION = validateProof(target_hash=TREE.rootHash, proof=PROOF)

    benchmark.pedantic(
        validate_proof,
        rounds=ROUNDS,
        iterations=ITERATIONS,
        warmup_rounds=WARMUP_ROUNDS
    )

    assert VALIDATION
