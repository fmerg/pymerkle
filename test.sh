#!/bin/bash

DEFAULT_STORAGE="inmemory"
DEFAULT_MAXSIZE=11
DEFAULT_THRESHOLD=2
DEFAULT_CAPACITY=$((1024 ** 3))

usage_string="usage: ./$(basename "$0") [options] [pytest_options]

Options
  --backend [inmemory|sqlite]   Storage backend (default: ${DEFAULT_STORAGE})
  --maxsize MAX                 Maximum size of tree fixtures (default: ${DEFAULT_MAXSIZE})
  --threshold WIDTH             Subroot cache threshold (default: ${DEFAULT_THRESHOLD})
  --capacity BYTES              Subroout cache capacity in bytes (default: 1GB)
  --extended                    Run tests against all supported hash algorithms;
                                otherwise only against sha256
  -h, --help                    Display help message and exit
"

set -e

usage() { echo -n "$usage_string" 1>&2; }

STORAGE="$DEFAULT_STORAGE"
MAXSIZE="$DEFAULT_MAXSIZE"
THRESHOLD="$DEFAULT_THRESHOLD"
CAPACITY="$DEFAULT_CAPACITY"

opts=()
while [[ $# -gt 0 ]]
do
    arg="$1"
    case $arg in
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
    --backend ${STORAGE} \
    --maxsize ${MAXSIZE} \
    --threshold ${THRESHOLD} \
    --capacity ${CAPACITY} \
    --cov-report term-missing \
    --cov=. \
    $opts
