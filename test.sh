#!/bin/bash

DEFAULT_ALGORITHM="sha256"
DEFAULT_STORAGE="inmemory"
DEFAULT_MAXSIZE=11
DEFAULT_THRESHOLD=2
DEFAULT_CAPACITY=$((1024 ** 3))

usage_string="usage: ./$(basename "$0") [options] [pytest_options]

Options
  --algorithm HASH              Hash algorithm to be used (default: ${DEFAULT_ALGORITHM})
  --backend [inmemory|sqlite]   Storage backend (default: ${DEFAULT_STORAGE})
  --maxsize MAX                 Maximum size of tree fixtures (default: ${DEFAULT_MAXSIZE})
  --threshold WIDTH             Subroot cache threshold (default: ${DEFAULT_THRESHOLD})
  --capacity BYTES              Subroout cache capacity in bytes (default: 1GB)
  --extended                    Run tests against all supported hash algorithms. NOTE: This
                                nullify the effect of the algorithm option
                                otherwise only against sha256
  -h, --help                    Display help message and exit
"

set -e

usage() { echo -n "$usage_string" 1>&2; }

ALGORITHM="$DEFAULT_ALGORITHM"
STORAGE="$DEFAULT_STORAGE"
MAXSIZE="$DEFAULT_MAXSIZE"
THRESHOLD="$DEFAULT_THRESHOLD"
CAPACITY="$DEFAULT_CAPACITY"

opts=()
while [[ $# -gt 0 ]]
do
    arg="$1"
    case $arg in
        --algorithm)
            ALGORITHM="$2"
            shift
            shift
            ;;
        --extended|-e)
            opts+=($arg)
            shift
            ;;
        --backend)
            STORAGE="$2"
            shift
            shift
            ;;
        --maxsize)
            MAXSIZE="$2"
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
        -h|--help)
            usage
            exit 0
            ;;
        *)
            opts+=($arg)
            shift
            ;;
    esac
done


python -m \
    pytest tests/ \
    --algorithm ${ALGORITHM} \
    --backend ${STORAGE} \
    --maxsize ${MAXSIZE} \
    --threshold ${THRESHOLD} \
    --capacity ${CAPACITY} \
    --cov-report term-missing \
    --cov=. \
    $opts
