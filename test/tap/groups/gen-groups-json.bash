#!/usr/bin/env bash

# make sure we have correct cwd
pushd $(dirname $0) > /dev/null


GRPS=$(echo $(ls -d */ | tr -d / | awk '{ print "\""$1"\"," }'))

echo "{" > groups.json
ls -1 ../tests/*-t | sed 's|../tests/||' | awk '{ print "  \""$0"\" : [ \"default\", __GRPS__ ]," }' >> groups.json
ls -1 ../tests_with_deps/deprecate_eof_support/*-t | sed 's|../tests_with_deps/deprecate_eof_support/||' | awk '{ print "  \""$0"\" : [ \"default\", __GRPS__ ]," }' >> groups.json
sed -i '$ s/.$//' groups.json
echo "}" >> groups.json
sed -i "s/__GRPS__/${GRPS%,}/" groups.json

