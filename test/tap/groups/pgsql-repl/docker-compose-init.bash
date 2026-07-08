#!/bin/bash
set -o pipefail

set -e

. constants

docker build -t postgres-tc:17 .
docker compose up -d

./bin/docker-pgsql-post.bash && ./bin/docker-proxy-post.bash
