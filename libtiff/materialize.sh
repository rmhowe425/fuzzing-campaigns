#!/usr/bin/env bash
set -euo pipefail

ROOT="${1:-.}"

find "$ROOT" -type f -name '*.tiff' | while read -r hexfile; do
  out="${hexfile%.tiff}.bin.tiff"

  # Skip already-materialized files
  if file "$hexfile" | grep -q 'TIFF image data'; then
    echo "[skip] already binary: $hexfile"
    continue
  fi

  # Strip whitespace, convert hex → binary
  tr -d ' \n\r\t' < "$hexfile" | xxd -r -p > "$out"

  # Sanity check
  if file "$out" | grep -q 'TIFF image data'; then
    echo "[ok] $hexfile → $out"
  else
    echo "[warn] $hexfile produced non-TIFF output"
  fi
done
