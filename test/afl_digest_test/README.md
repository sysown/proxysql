## Description

This folder provides a AFL++ stability test for fuzzy testing 'mysql_query_digest_and_first_comment_2'
implementation.

## Usage

For compiling test it's enough to run the following commands in ProxySQL main WORKSPACE folder:

```
docker run -tid -v $(pwd):/src aflplusplus/aflplusplus
docker exec -it $(CONTAINER_ID) /bin/bash
cd /src/test/afl_digest_test/
make
```

Then for launching an individual instance of `afl-fuzz` it's enough to run:

```
mkdir output
afl-fuzz -M main-$HOSTNAME -i inputs/ -o output/ -- ./afl_test -d 1 -l 1 -n 1 -s 50 -g 0 -G 0
```

Where the options that can be specified for the fuzzing test are:

```
AFL fuzz testing for digest parsing

USAGE: afl_test [OPTIONS]

OPTIONS:

-d, --replace-digits ARG          Query digest 'NoDigits'
-G, --groups-grouping-limit ARG   Query digest 'GroupsGroupingLimit'
-g, --grouping-limit ARG          Query digest 'GroupingLimit'
-h, -help, --help, --usage        Display usage instructions.
-l, --lowercase ARG               Query digest 'LowerCase'
-n, --replace-null ARG            Query digest 'ReplaceNULL'
-s, --digest-size ARG             Query digest 'MaxLength'

```

They can be optioned also by running `./afl_test -h`.

## Parallel testing

1\. For launching multiple instances of `afl-fuzz` the `launch_tests.sh` and `stop_tests.sh` scripts could be used.
2\. For checking the overall progress of the parallel testing the following command can be used:
```
afl-whatsup -s output
```
