#!/bin/bash


DBFILE="./benchmarks/merkle.db"

usage_string="
usage: ./$(basename "$0") [options]

Run benchmarks against the database ${DBFILE} of ten million
entries

Results saved in ./.bencmarks/Linux-CPyhton-3.*

Options
  --dbfile          Database to use (default: ${DBFILE}
  --size            Nr entries to consider (default: 10,000,000)
  --index           Base index for proof operations. If not provided, it will
                    be set equal to the ceil(size/2)
  --randomize       Randomize function input per round. Useful for
                    realistically capturing the effect of caching. WARNING:
                    This will nullify the effect of the index option
  -r, --rounds      Nr rounds per benchmark (default: 100)
  -o, --operation   Benchmark a single operation: root, state, inclusion,
                    consistency. If not provided, it benchmarks everything
  -c, --compare     Compare against last saved benchmark
  -ns, --no-save    Do not save results
  -a, --algorithm   Hash algorithm used by the tree (default: sha256)
  -h, --help        Display help message and exit
"

set -e

usage() { echo -n "$usage_string" 1>&2; }


BENCHMARK="benchmarks/test_perf.py"
SIZE=$((10 ** 7))
ROUNDS=100
ALGORITHM=sha256
OPERATION=""
SAVE=true

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
        -r|--rounds)
            ROUNDS="$2"
            shift
            shift
            ;;
        -a|--algorithm)
            ALGORITHM="$2"
            shift
            shift
            ;;
        -c|--compare)
            opts+=(--benchmark-compare)
            shift
            ;;
        -o|--operation)
            OPERATION="$2"
            shift
            shift
            ;;
        --randomize)
            opts+=" $arg"
            shift
            ;;
        -ns|--no-save)
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
    --quiet \
    --benchmark-only \
    --benchmark-name=short \
    --benchmark-warmup=off \
    --benchmark-columns=min,max,mean,median,outliers,rounds,ops \
    $opts
