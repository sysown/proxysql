#!/usr/bin/env bash

# make sure we have correct cwd
pushd $(dirname $0)

# symlink all files from ../tests
for T in $(ls -1 ../tests/); do
#	echo "ln -fsT ../tests/$T $T"
	ln -fsT ../tests/$T $T
done

# remove irelevant
#rm -f test_*-t
