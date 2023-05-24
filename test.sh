#!/bin/bash

usage_string="usage: ./$(basename "$0") [pytest_options] [--extended]

Options
  --backend [inmemory|sqlite]   Tree storage backend (default: inmemory)
  --extended                    If provided, run tests against all combinations
                                of hash aglorithms and encoding schemes;
                                otherwise run only against UTF-8, UTF-16 and
                                UTF-32 (default: false)
  -h, --help                    Display help message and exit
"

set -e

BACKEND="inmemory"

usage() { echo -n "$usage_string" 1>&2; }

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
            BACKEND="$2"
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


python3 -m \
  pytest tests/ \
  --backend ${BACKEND} \
  --cov-report term-missing \
  --cov=. \
  $opts
