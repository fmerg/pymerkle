#!/bin/bash


DEFAULT_DBFILE="./benchmarks/merkle.db"
DEFAULT_SIZE=$((10 ** 6))
DEFAULT_ALGORITHM=sha256
DEFAULT_MEMORY=true
DEFAULT_TIMING=false
DEFAULT_ROUNDS=1
DEFAULT_RANDOMIZE=false
DEFAULT_ACTION="root"
DEFAULT_GRAPH=false
DEFAULT_OPTIMIZATIONS=true
DEFAULT_CACHE=true
DEFAULT_THRESHOLD=128
DEFAULT_CAPACITY=$((1024 ** 3))
DEFAULT_FOLDER='./profiler/.results'

usage_string="
usage: ./$(basename "$0") [options]

Profile running ./profiler against the database ${DEFAULT_DBFILE}
of ten million entries.

Results saved in "$DEFAULT_FOLDER".

Options
  --dbfile DB               Database to use (default: ${DEFAULT_DBFILE})
  --size SIZE               Nr entries to consider (default: ${DEFAULT_SIZE})
  --index INDEX             Base index for proof operations. If not provided,
                            it will be set equal to the ceil(size/2)
  --rounds ROUNDS           Nr rounds (default: ${DEFAULT_ROUNDS})
  --algorithm HASH          Hash algorithm used by the tree (default: ${DEFAULT_ALGORITHM})
  --threshold WIDTH         Cache threshold (default: ${DEFAULT_THRESHOLD})
  --capacity MAXSIZE        Cache capacity in bytes (default: 1GiB)
  --operation OP            Operation to profile: root, state, inclusion,
                            consistency (default: ${DEFAULT_ACTION})
  --disable-optimizations   Use unoptimized version of core operations
  --disable-cache           Disable caching
  -r, --randomize           Randomize function input per round. Useful for
                            capturing the effect of caching. WARNING:
                            This will nullify the effect of the index option
  -t, --time                Measure also time delay per line
  -sm, --skip-memory        Skip memory allocation measurements
  -g, --graph               Create flame graph
  -h, --help                Display help message and exit
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
    outfile="${FOLDER}/timing.prof"

    kernprof \
        --view \
        --unit 1e-6 \
        --line-by-line \
        --skip-zero \
        --outfile ${outfile} \
        ${OPERATION}
}


profile_memory__mprof() {
    outfile="${FOLDER}/memory.prof"

    rm -f ${outfile}

    mprof run \
        --interval 0.1 \
        --backend psutil \
        --output ${outfile} \
        ${OPERATION}

    mprof peak ${outfile}

    python -m memory_profiler \
        --precision 3 \
        ${OPERATION}

    if [ ${GRAPH} == true ]; then
        mprof plot \
            --flame \
            --title ${ACTION} \
            --output ${FOLDER}/memory.png \
            ${outfile}
    fi
}


DBFILE="$DEFAULT_DBFILE"
SIZE="$DEFAULT_SIZE"
ALGORITHM="$DEFAULT_ALGORITHM"
MEMORY="$DEFAULT_MEMORY"
TIMING="$DEFAULT_TIMING"
ROUNDS="$DEFAULT_ROUNDS"
RANDOMIZE="$DEFAULT_ROUNDS"
ACTION="$DEFAULT_ALGORITHM"
GRAPH="$DEFAULT_GRAPH"
OPTIMIZATIONS="$DEFAULT_OPTIMIZATIONS"
CACHE="$DEFAULT_CACHE"
THRESHOLD="$DEFAULT_THRESHOLD"
CAPACITY="$DEFAULT_CAPACITY"
FOLDER="$DEFAULT_FOLDER"

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
        --operation)
            ACTION="$2"
            shift
            shift
            ;;
        --capacity)
            CAPACITY="$2"
            shift
            shift
            ;;
        --rounds)
            ROUNDS="$2"
            shift
            shift
            ;;
        --disable-optimizations)
            OPTIMIZATIONS=false
            shift
            ;;
        --disable-cache)
            CACHE=false
            shift
            ;;
        -r|--randomize)
            RANDOMIZE=true
            shift
            ;;
        -t|--time)
            TIMING=true
            shift
            ;;
        -sm|--skip-memory)
            MEMORY=false
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
    --rounds ${ROUNDS} \
    --threshold ${THRESHOLD} \
    --capacity ${CAPACITY}
"

if [ ${RANDOMIZE} == true ]; then
    SCRIPT+=" --randomize"
fi

if [ ${OPTIMIZATIONS} == false ]; then
    SCRIPT+=" --disable-optimizations"
fi

if [ ${CACHE} == false ]; then
    SCRIPT+=" --disable-cache"
fi


OPTIONS=$(resolve_options "$ACTION")
OPERATION="${SCRIPT} ${ACTION} ${OPTIONS}"


mkdir -p ${FOLDER}

if [ ${TIMING} == true ]; then
    profile_time
fi


if [ ${MEMORY} == true ]; then
    profile_memory__mprof
fi
