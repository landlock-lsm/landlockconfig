#!/usr/bin/env bash

set -u -e -o pipefail

BASE_DIR=$(dirname "${BASH_SOURCE[0]}")

check-jsonschema --schemafile "${BASE_DIR}/landlockconfig.json" "$@"
