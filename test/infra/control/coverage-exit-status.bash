#!/bin/bash

coverage_exit_status() {
    local test_exit="${1:?test exit status required}"
    local coverage_exit="${2:?coverage exit status required}"

    if [ "${test_exit}" -ne 0 ]; then
        return "${test_exit}"
    fi
    return "${coverage_exit}"
}
