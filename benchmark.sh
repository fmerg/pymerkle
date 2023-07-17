#!/bin/bash


DEFAULT_DBFILE="./benchmarks/merkle.db"
DEFAULT_BENCHMARK="benchmarks/test_perf.py"
DEFAULT_SIZE=$((10 ** 6))
DEFAULT_ROUNDS=100
DEFAULT_THRESHOLD=128
DEFAULT_CAPACITY=$((1024 ** 3))
DEFAULT_ALGORITHM=sha256
DEFAULT_OPERATION=""
DEFAULT_SAVE=true

usage_string="
usage: ./$(basename "$0") [options]

Run benchmarks against ${DEFAULT_DBFILE}

Results saved in ./.bencmarks/Linux-CPyhton-3.*

Tree configuration
  --algorithm HASH          Hash algorithm used by the tree (default: ${DEFAULT_ALGORITHM})
  --threshold WIDTH         Subroot cache threshold (default: ${DEFAULT_THRESHOLD})
  --capacity MAXSIZE        Subroout cache capacity in bytes (default: 1GiB)
  --disable-optimizations   Use unoptimized version of core operations
  --disable-cache           Disable caching

Benchmarking options
  --dbfile DB               Database to use (default: ${DEFAULT_DBFILE})
  --operation OP            Benchmark a single operation: root, state, inclusion,
                            consistency. If not provided, it benchmarks everything
  --size SIZE               Nr entries to consider (default: ${DEFAULT_SIZE})
  --index INDEX             Base index for proof operations. If not provided,
                            it will be set equal to ceil(size/2)
  --rounds ROUNDS           Nr rounds per benchmark (default: ${DEFAULT_ROUNDS})
  -r, --randomize           Randomize function input per round. Useful for
                            capturing the effect of caching. WARNING: This will
                            nullify the effect of the index option
  -c, --compare             Compare against last saved benchmark
  -ss, --skip-save          Do not save results
  -h, --help                Display help message and exit

Examples:
  $ ./benchmark.sh --rounds 10 --skip-save --size 1000000 --randomize --disable-optimizations
  $ ./benchmark.sh --rounds 10 --skip-save --size 1000000 --randomize --disable-cache
  $ ./benchmark.sh --rounds 10 --skip-save --size 1000000 --randomize

"

set -e

usage() { echo -n "$usage_string" 1>&2; }


DBFILE="$DEFAULT_DBFILE"
BENCHMARK="$DEFAULT_BENCHMARK"
SIZE="$DEFAULT_SIZE"
ROUNDS="$DEFAULT_ROUNDS"
THRESHOLD="$DEFAULT_THRESHOLD"
CAPACITY="$DEFAULT_CAPACITY"
ALGORITHM="$DEFAULT_ALGORITHM"
OPERATION="$DEFAULT_OPERATION"
SAVE="$DEFAULT_SAVE"


opts=()
while [[ $# -gt 0 ]]
do
    arg="$1"
    case $arg in
        --dbfile)
            DBFILE="$2"
            shift
            shift
            ;;
        --size)
            SIZE="$2"
            shift
            shift
            ;;
        --index)
            INDEX="$2"
            shift
            shift
            ;;
        --rounds)
            ROUNDS="$2"
            shift
            shift
            ;;
        --algorithm)
            ALGORITHM="$2"
            shift
            shift
            ;;
        --threshold)
            THRESHOLD="$2"
            shift
            shift
            ;;
        --capacity)
            CAPACITY="$2"
            shift
            shift
            ;;
        --operation)
            OPERATION="$2"
            shift
            shift
            ;;
        --disable-optimizations)
            opts+=" $arg"
            shift
            ;;
        --disable-cache)
            opts+=" $arg"
            shift
            ;;
        -r|--randomize)
            opts+=" $arg"
            shift
            ;;
        -c|--compare)
            opts+=(--benchmark-compare)
            shift
            ;;
        -ss|--skip-save)
            SAVE=false
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            opts+=" $arg"
            shift
            ;;
    esac
done


if [ ! -f "$DBFILE" ]; then
    echo "No database found at ${DBFILE}"
    exit 1
fi


if [ -z ${INDEX} ]; then
    INDEX=$(($(($SIZE + 1))/2))
fi


if [ ${OPERATION} ]; then
    BENCHMARK="${BENCHMARK}::test_${OPERATION}"
fi


if [ ${SAVE} == true ]; then
    opts+=" --benchmark-autosave"
fi


python -m pytest $BENCHMARK \
    --dbfile $DBFILE \
    --size $SIZE \
    --index $INDEX \
    --rounds $ROUNDS \
    --algorithm $ALGORITHM \
    --threshold $THRESHOLD \
    --capacity $CAPACITY \
    --quiet \
    --benchmark-only \
    --benchmark-name=short \
    --benchmark-warmup=off \
    --benchmark-columns=min,max,mean,median,outliers,rounds,ops \
    $opts
