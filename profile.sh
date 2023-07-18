#!/bin/bash


DEFAULT_ALGORITHM=sha256
DEFAULT_THRESHOLD=128
DEFAULT_CAPACITY=$((1024 ** 3))
DEFAULT_OPTIMIZATIONS=true
DEFAULT_CACHE=true
DEFAULT_DBFILE="./benchmarks/merkle.db"
DEFAULT_ACTION="root"
DEFAULT_SIZE=$((10 ** 6))
DEFAULT_ROUNDS=1
DEFAULT_RANDOMIZE=false
DEFAULT_TIMING=false
DEFAULT_LINE=false
DEFAULT_GRAPH=false
DEFAULT_RESULTS="./profiler/.results"

usage_string="
usage: ./$(basename "$0") [options]

Profile by running the ./profiler script against ${DEFAULT_DBFILE}

Default mode is memory profiling using valgrind. By appropriately combining the
\"--time\" and \"--line\" options, you can achieve any of the following modes:

  - vague time profiling using the unix time utility
  - line-by-line memory profiling using the memory_profiler python package
  - line-by-line time profiling using the line_profiler python package

Results saved in "$DEFAULT_RESULTS"

Tree configuration
  --algorithm HASH          Hash algorithm used by the tree (default: ${DEFAULT_ALGORITHM})
  --threshold WIDTH         Cache threshold (default: ${DEFAULT_THRESHOLD})
  --capacity MAXSIZE        Cache capacity in bytes (default: 1GiB)
  --disable-optimizations   Use unoptimized version of core operations
  --disable-cache           Disable caching

Profiler options
  --dbfile DB               Database to use (default: ${DEFAULT_DBFILE})
  --operation OP            Operation to profile: root, state, inclusion,
                            consistency (default: ${DEFAULT_ACTION})
  --size SIZE               Nr entries to consider (default: ${DEFAULT_SIZE})
  --index INDEX             Base index for proof operations. If not provided,
                            it will be set equal to ceil(size/2)
  --rounds ROUNDS           Nr rounds (default: ${DEFAULT_ROUNDS})
  -r, --randomize           Randomize function input per round. Useful for
                            capturing the effect of caching. WARNING:
                            This will nullify the effect of the index option
  -t, --time                Profile execution times instead of memory allocations
  -l, --line                Line-by-line profiling
  -g, --graph               Create flame graph in case of line-by-line memory
                            profiling
  -h, --help                Display help message and exit

"

set -e

usage() { echo -n "$usage_string" 1>&2; }


resolve_action_options() {
    if [ -z ${INDEX} ]; then
        INDEX=$(($(($SIZE + 1))/2))
    fi

    case $1 in
        root)
            options="--start ${INDEX} --limit ${SIZE}"
            ;;
        state)
            options="--size ${SIZE}"
            ;;
        inclusion)
            options="--index ${INDEX} --size ${SIZE}"
            ;;
        consistency)
            options="--size1 ${INDEX} --size2 ${SIZE}"
            ;;
        *)
            echo "Invalid operation: ${ACTION}"
            usage
            exit 1
            ;;
    esac

    echo $options
}


resolve_operation() {
    script="profiler/__main__.py --dbfile ${DBFILE} --algorithm ${ALGORITHM} \
                                 --capacity ${CAPACITY} --threshold ${THRESHOLD} \
                                 --rounds ${ROUNDS}
    "

    if [ ${RANDOMIZE} == true ]; then
        script+=" --randomize"
    fi

    if [ ${OPTIMIZATIONS} == false ]; then
        script+=" --disable-optimizations"
    fi

    if [ ${CACHE} == false ]; then
        script+=" --disable-cache"
    fi

    options=$(resolve_action_options "$ACTION")
    echo "${script} ${ACTION} ${options}"
}


profile_time_line_by_line() {
    outfile="${RESULTS}/ltime.prof"

    kernprof \
        --view \
        --unit 1e-6 \
        --line-by-line \
        --skip-zero \
        --outfile ${outfile} \
        $1
}


profile_time() {
    $(which time) \
        --verbose \
        python $1
}


profile_memory_line_by_line() {
    outfile="${RESULTS}/lmem.prof"

    rm -f ${outfile}

    # mprof run \
    #     --interval 0.1 \
    #     --backend psutil \
    #     --output ${outfile} \
    #     $1
    # mprof peak ${outfile}

    python -m memory_profiler \
        --precision 3 \
        $1

    if [ ${GRAPH} == true ]; then
        mprof plot \
            --flame \
            --title ${ACTION} \
            --output ${RESULTS}/memory.png \
            ${outfile}
    fi
}


profile_memory() {
    valgrind \
        --tool=massif \
        --heap=yes \
        --massif-out-file="${RESULTS}/massif.out.%p" \
        python $1

    infile=$(find ${RESULTS}/massif.out.* \
        -printf "%t - %p\n" \
        | sort -nr \
        | awk 'NR==1 {print $7}')

    massif-visualizer "${infile}"&
}


resolve_profiler() {
    profiler="profile"

    if [ ${TIMING} == true ]; then
        profiler+="_time"
    else
        profiler+="_memory"
    fi

    if [ ${LINE} == true ]; then
        profiler+="_line_by_line"
    fi

    echo $profiler
}


ALGORITHM="$DEFAULT_ALGORITHM"
THRESHOLD="$DEFAULT_THRESHOLD"
CAPACITY="$DEFAULT_CAPACITY"
OPTIMIZATIONS="$DEFAULT_OPTIMIZATIONS"
CACHE="$DEFAULT_CACHE"
DBFILE="$DEFAULT_DBFILE"
ACTION="$DEFAULT_ACTION"
SIZE="$DEFAULT_SIZE"
ROUNDS="$DEFAULT_ROUNDS"
RANDOMIZE="$DEFAULT_ROUNDS"
MEMORY="$DEFAULT_MEMORY"
TIMING="$DEFAULT_TIMING"
LINE="$DEFAULT_LINE"
GRAPH="$DEFAULT_GRAPH"
RESULTS="$DEFAULT_RESULTS"

while [[ $# -gt 0 ]]
do
    arg="$1"
    case $arg in
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
        --disable-optimizations)
            OPTIMIZATIONS=false
            shift
            ;;
        --disable-cache)
            CACHE=false
            shift
            ;;
        --dbfile)
            DBFILE="$2"
            if [ ! -f "$DBFILE" ]; then
                echo "No database found at ${DBFILE}"
                exit 1
            fi
            shift
            shift
            ;;
        --operation)
            ACTION="$2"
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
        -r|--randomize)
            RANDOMIZE=true
            shift
            ;;
        -t|--time)
            TIMING=true
            shift
            ;;
        -l|--line)
            LINE=true
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

mkdir -p ${RESULTS}

operation=$(resolve_operation)
profiler=$(resolve_profiler)

"$profiler" "$operation"
