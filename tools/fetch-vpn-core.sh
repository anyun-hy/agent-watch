#!/bin/bash
# Fetch and verify the pinned official sing-box arm64 binary for bundling as
# `Contents/Resources/watch-vpn-core`. Never installs or modifies host VPNs.
set -euo pipefail

SING_BOX_VERSION="${SING_BOX_VERSION:-1.11.15}"
OUTPUT=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --output)
      [[ $# -ge 2 ]] || { echo "Missing value for --output" >&2; exit 2; }
      OUTPUT=$2
      shift 2
      ;;
    --version)
      [[ $# -ge 2 ]] || { echo "Missing value for --version" >&2; exit 2; }
      SING_BOX_VERSION=$2
      shift 2
      ;;
    *)
      echo "Unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

[[ -n "$OUTPUT" ]] || { echo "Usage: tools/fetch-vpn-core.sh --output <path>" >&2; exit 2; }

ARCHIVE_NAME="sing-box-${SING_BOX_VERSION}-darwin-arm64.tar.gz"
BASE_URL="https://github.com/SagerNet/sing-box/releases/download/v${SING_BOX_VERSION}"
TMP_DIR=$(mktemp -d "${TMPDIR:-/tmp}/cw-vpn-core.XXXXXX")
trap 'rm -rf "$TMP_DIR"' EXIT

echo "Fetching sing-box v${SING_BOX_VERSION} (darwin-arm64)..."
curl -fsSL --retry 3 --retry-delay 2 "${BASE_URL}/${ARCHIVE_NAME}" -o "${TMP_DIR}/${ARCHIVE_NAME}"

# Verify archive checksum against official release checksums.txt if published,
# plus any caller-pinned CW_VPN_CORE_ARCHIVE_SHA256.
ACTUAL_SHA=$(/usr/bin/shasum -a 256 "${TMP_DIR}/${ARCHIVE_NAME}" | /usr/bin/awk '{print $1}')
if [[ -n "${CW_VPN_CORE_ARCHIVE_SHA256:-}" && "$ACTUAL_SHA" != "$CW_VPN_CORE_ARCHIVE_SHA256" ]]; then
  echo "Pinned SHA-256 mismatch for ${ARCHIVE_NAME}: expected ${CW_VPN_CORE_ARCHIVE_SHA256}, got ${ACTUAL_SHA}" >&2
  exit 1
fi
if curl -fsSL --retry 2 "${BASE_URL}/checksums.txt" -o "${TMP_DIR}/checksums.txt" 2>/dev/null; then
  EXPECTED_SHA=$(/usr/bin/awk -v f="${ARCHIVE_NAME}" '$2 == f || $2 == ("*" f) { print $1; exit }' "${TMP_DIR}/checksums.txt")
  if [[ -n "$EXPECTED_SHA" && "$ACTUAL_SHA" != "$EXPECTED_SHA" ]]; then
    echo "Upstream checksums.txt mismatch for ${ARCHIVE_NAME}: expected ${EXPECTED_SHA}, got ${ACTUAL_SHA}" >&2
    exit 1
  fi
fi

/usr/bin/tar -xzf "${TMP_DIR}/${ARCHIVE_NAME}" -C "${TMP_DIR}"
BIN_PATH="${TMP_DIR}/sing-box-${SING_BOX_VERSION}-darwin-arm64/sing-box"
[[ -f "$BIN_PATH" && ! -L "$BIN_PATH" ]] || { echo "Extracted sing-box binary missing" >&2; exit 1; }

ARCHS=$(/usr/bin/lipo -archs "$BIN_PATH" | /usr/bin/xargs)
[[ "$ARCHS" == "arm64" ]] || { echo "Unexpected sing-box archs: ${ARCHS}" >&2; exit 1; }

chmod 700 "$BIN_PATH"
"$BIN_PATH" version | head -n 3

mkdir -p "$(dirname "$OUTPUT")"
cp "$BIN_PATH" "$OUTPUT"
chmod 700 "$OUTPUT"
printf 'Verified watch-vpn-core (sing-box %s, sha256=%s) -> %s\n' "$SING_BOX_VERSION" "$(/usr/bin/shasum -a 256 "$OUTPUT" | /usr/bin/awk '{print $1}')" "$OUTPUT"
