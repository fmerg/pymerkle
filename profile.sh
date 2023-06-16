#!/bin/bash


DBFILE="./benchmarks/merkle.db"

usage_string="
usage: ./$(basename "$0") [options]

Profile memory allocation running ./profiler/__main__.py against the
database ${DBFILE} of ten million entries

Results saved in ./profiler/.results

Options
  --dbfile          Database to use (default: ${DBFILE}
  --size            Nr entries to consider (default: 10,000,000)
  --index           Base index for proof operations. If not provided, it will
                    be set equal to the ceil(size/2)
  -o, --operation   Operation to profile: root, state, inclusion,
                    consistency (default: root)
  --rounds          Nr rounds (default: 1)
  --randomize       Randomize function input per round. Useful for
                    realistically capturing the effect of caching. WARNING:
                    This will nullify the effect of the index option
  -a, --algorithm   Hash algorithm used by the tree (default: sha256)
  -t, --time        Measure also time delay per line
  -nm, --no-memory  Skip memory allocation measurements
  -g, --graph       Create flame graph
  -h, --help        Display help message and exit
"

set -e

usage() { echo -n "$usage_string" 1>&2; }


resolve_options() {
  case $1 in
      root)
          OPTIONS="--start ${INDEX} --end ${SIZE}"
          ;;
      state)
          OPTIONS="--size ${SIZE}"
          ;;
      inclusion)
          OPTIONS="--index ${INDEX} --size ${SIZE}"
          ;;
      consistency)
          OPTIONS="--size1 ${INDEX} --size2 ${SIZE}"
          ;;
      *)
          echo "Invalid operation: ${ACTION}"
          usage
          exit 1
          ;;
  esac

  echo $OPTIONS
}


profile_time() {
    kernprof \
        --view \
        --unit 1e-6 \
        --line-by-line \
        --skip-zero \
        --outfile ${FOLDER}/timing.prof \
        ${OPERATION}
}


profile_memory() {
    mprof run \
        --interval 0.1 \
        --backend psutil \
        --output ${FOLDER}/memory.dat \
        ${OPERATION}

    mprof peak ${FOLDER}/memory.dat

    python -m memory_profiler \
        --precision 3 \
        ${OPERATION}

    if [ ${GRAPH} == true ]; then
        mprof plot \
            --flame \
            --title ${ACTION} \
            --output ${FOLDER}/memory.png \
            ${FOLDER}/memory.dat
    fi
}


SIZE=$((10 ** 7))
ALGORITHM=sha256
MEMORY=true
TIMING=false
ROUNDS=1
RANDOMIZE=false
ACTION="root"
GRAPH=false
FOLDER='./profiler/.results'

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
        --randomize)
            RANDOMIZE=true
            shift
            ;;
        -a|--algorithm)
            ALGORITHM="$2"
            shift
            shift
            ;;
        -t|--time)
            TIMING=true
            shift
            ;;
        -nm|--no-memory)
            MEMORY=false
            shift
            ;;
        -o|--operation)
            ACTION="$2"
            shift
            shift
            ;;
        -g|--graph)
            GRAPH=true
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Invalid argument: ${arg}"
            usage
            exit 1
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


SCRIPT="profiler/__main__.py \
    --dbfile ${DBFILE} \
    --algorithm ${ALGORITHM} \
    --rounds ${ROUNDS}
"

if [ ${RANDOMIZE} == true ]; then
    SCRIPT+=" --randomize"
fi


OPTIONS=$(resolve_options "$ACTION")
OPERATION="${SCRIPT} ${ACTION} ${OPTIONS}"


mkdir -p ${FOLDER}

if [ ${TIMING} == true ]; then
    profile_time
fi


if [ ${MEMORY} == true ]; then
    profile_memory
fi
