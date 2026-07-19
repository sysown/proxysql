#!/usr/bin/env bash
set -e

# ProxySQL's Admin port is available before module startup has fully settled.
sleep 5
