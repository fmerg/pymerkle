#!/bin/bash

usage_string="usage: ./$(basename "$0") [pytest_options] [--extended]

Options
  --extended  If provided, tests run against all combinations of hash
              algorithms and encoding schemes; otherwise run only against
              encodings UTF-8, UTF-16 and UTF-32
  -h, --help  Display help message and exit
"

set -e

usage() { echo -n "$usage_string" 1>&2; }

args=()
while [[ $# -gt 0 ]]
do
    arg="$1"
    case $arg in
        --extended|-e)
            args+=($arg)
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            args+=($arg)
            shift
            ;;
    esac
done

python3 -m \
  pytest tests/ \
  --cov-report term-missing \
  --cov=. \
  $args
