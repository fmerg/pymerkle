#!/bin/bash

python3 -m pytest benchmarks/ \
  --benchmark-only \
  --benchmark-name='short' \
  $*
