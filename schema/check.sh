#!/usr/bin/env bash

set -u -e -o pipefail

BASE_DIR=$(dirname "${BASH_SOURCE[0]}")

if [[ $# -eq 0 ]]; then
    echo "ERROR: No files to check" >&2
    exit 1
fi

for file in "$@"; do
    if [[ ! -r "${file}" ]]; then
        echo "ERROR: Invalid file: ${file}" >&2
        exit 1
    fi

    diff -u "${file}" <(jq < "${file}") || {
        echo
        echo "ERROR: Invalid formatting" >&2
        exit 1
    }

    check-jsonschema --schemafile "${BASE_DIR}/landlockconfig.json" "${file}" || {
        echo
        echo "ERROR: Not validated by schema: ${file}" >&2
        exit 1
    }
done
