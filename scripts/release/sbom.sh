#!/bin/sh
# Copyright (c) 2026 TrueSignal Deception. All rights reserved.
#
# CycloneDX SBOM for a container image or a binary (F-004), written with Trivy
# and checked to be a non-empty CycloneDX document before it is published.
#   sbom.sh image <ref> <out.cdx.json>
#   sbom.sh binary <file> <out.cdx.json>
#   sbom.sh verify <file.cdx.json>
set -eu
verify() {
	jq -e '.bomFormat == "CycloneDX" and (.specVersion | type == "string") and ((.components // []) | length > 0)' "$1" >/dev/null ||
		{ echo "sbom: $1 is not a non-empty CycloneDX document" >&2; return 1; }
}
case "${1:-}" in
image)
	trivy image --quiet --format cyclonedx --output "${3:?out}" "${2:?image ref}"
	verify "$3"
	;;
binary)
	d=$(mktemp -d); trap 'rm -rf "$d"' EXIT
	cp "${2:?binary}" "$d/"
	trivy rootfs --quiet --format cyclonedx --output "${3:?out}" "$d"
	verify "$3"
	;;
verify) verify "${2:?file}" ;;
*) echo "usage: sbom.sh image|binary <target> <out> | verify <file>" >&2; exit 2 ;;
esac
