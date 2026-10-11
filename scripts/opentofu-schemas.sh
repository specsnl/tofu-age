#!/usr/bin/env bash
#
# Keeps OpenTofu's external encryption method schemas, vendored under
# internal/protocol/testdata, in step with OpenTofu.
#
# Usage: opentofu-schemas.sh update <version>
#        opentofu-schemas.sh check <version>
#
# update downloads the schemas at the OpenTofu release <version> into testdata.
# check compares testdata with the schemas at <version>, then with those at the
# latest OpenTofu release. A newer release with the same schemas is not an
# update: the files are what the tests run against, not the version number.
#
# Exit codes:
#   0 - testdata matches <version>, and the latest release has the same schemas
#   1 - testdata needs updating
#   2 - the update or check itself failed
set -euo pipefail

readonly repo=opentofu/opentofu
readonly upstream_path=internal/encryption/method/external/protocol
readonly schemas=(header input output)

if [[ $# -ne 2 ]] || [[ "$1" != update && "$1" != check ]]; then
    echo "Usage: $0 <update|check> <version>" >&2
    exit 2
fi

mode="$1"
version="$2"

if [[ ! "${version}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "Invalid OpenTofu version: '${version}'" >&2
    exit 2
fi

testdata="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/internal/protocol/testdata"
tmp="$(mktemp -d)"
trap 'rm -rf "${tmp}"' EXIT

# download <tag> <dir> fetches every schema at <tag> into <dir>, unchanged.
download() {
    mkdir -p "$2"

    for name in "${schemas[@]}"; do
        if ! curl -sSfL -o "$2/${name}.schema.json" \
            "https://raw.githubusercontent.com/${repo}/$1/${upstream_path}/${name}.schema.json"; then
            echo "Failed to download the ${name} schema at OpenTofu $1" >&2
            exit 2
        fi
    done
}

# matches <tag> <dir> reports whether testdata holds exactly the schemas in
# <dir>, and prints the difference when it does not.
matches() {
    local status=0

    for name in "${schemas[@]}"; do
        diff -u \
            --label "testdata/${name}.schema.json" "${testdata}/${name}.schema.json" \
            --label "OpenTofu $1/${name}.schema.json" "$2/${name}.schema.json" \
            || status=1
    done

    return "${status}"
}

if [[ "${mode}" == update ]]; then
    download "${version}" "${tmp}/${version}"
    cp "${tmp}/${version}/"*.schema.json "${testdata}/"

    echo "Downloaded the schemas at OpenTofu ${version} into internal/protocol/testdata"
    echo "Review the diff and run the tests: a new protocol version needs changes in internal/protocol too."
    exit 0
fi

download "${version}" "${tmp}/${version}"

if ! matches "${version}" "${tmp}/${version}"; then
    echo "internal/protocol/testdata does not match the schemas at OpenTofu ${version}; run: task schemas:update"
    exit 1
fi

# /releases/latest redirects to the tag of the latest (non-prerelease) release, which avoids the API rate limit.
if ! latest_url="$(curl -sSfL -o /dev/null -w '%{url_effective}' "https://github.com/${repo}/releases/latest")"; then
    echo "Failed to fetch the latest OpenTofu release" >&2
    exit 2
fi

latest="${latest_url##*/tag/}"
if [[ ! "${latest}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "Unexpected latest release URL: ${latest_url}" >&2
    exit 2
fi

if [[ "${latest}" == "${version}" ]]; then
    echo "The schemas are up to date (OpenTofu ${version})"
    exit 0
fi

download "${latest}" "${tmp}/${latest}"

if matches "${latest}" "${tmp}/${latest}"; then
    echo "The schemas are up to date: OpenTofu ${latest} has the same schemas as ${version}"
    exit 0
fi

echo "OpenTofu ${latest} changed the schemas (pinned: ${version})"
echo "Release: ${latest_url}"
echo "Set OPENTOFU_SCHEMAS_VERSION in taskfiles/Taskfile.schemas.yml, then run: task schemas:update"
exit 1
