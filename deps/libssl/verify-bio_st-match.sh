#!/bin/bash

# make sure we have correct cwd
pushd $(dirname $0) &>/dev/null
trap 'popd &>/dev/null' EXIT

echo "extracting 'struct bio_st' from './deps/libssl/openssl/crypto/bio/bio_local.h'"
DEPBIOST=$(cd ../../; cat ./deps/libssl/openssl/crypto/bio/bio_local.h | sed -n '/^struct bio_st {/,/}/p')

echo "extracting 'struct bio_st' from './lib/mysql_data_stream.cpp'"
LIBBIOST=$(cd ../../; cat ./lib/mysql_data_stream.cpp | sed '/^\/\*/,/*\//d' | sed -n '/^struct bio_st {/,/}/p')

echo -n "Comparing ... "
if [[ "$LIBBIOST" == "$DEPBIOST" ]]; then
	echo "PASS - bio_st is a match!";
else
	echo "FAIL - bio_st does not match!";
	exit 1
fi
