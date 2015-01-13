#!/bin/bash
#
# XSS Sample Tests
#
set -e
${VALGRIND} ./reader -i ../data/false_*.txt
