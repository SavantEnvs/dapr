#!/usr/bin/env bash
#
# mayhem/build.sh — build dapr's CEL expression PARSER (pkg/expr) as a sanitized
# libFuzzer binary (OSS-Fuzz Go path: go-118-fuzz-build -libfuzzer archive +
# clang++ ASan link), plus the known-answer oracle mayhem/test.sh runs
# (/mayhem/expr_kat), built by the SAME go-118-fuzz-build command and the SAME
# link line as the fuzz target so test.sh exercises the graded build flavor.
#
# Runs inside the commit image (GO mayhem/Dockerfile) as `mayhem` in /mayhem.
# GOROOT/GOPATH/GOMODCACHE are pinned by the Dockerfile ENV under /opt/toolchains
# (absolute, $HOME-independent — so the offline PATCH re-run finds the cache).
#
# AIR-GAPPED CONTRACT (SPEC §6.5): the PATCH tier re-runs THIS script OFFLINE.
#   - This FIRST build (online) fills $GOMODCACHE (go mod tidy + go get shim).
#   - GOPROXY points at the in-image module cache's file proxy FIRST, network
#     LAST, so the offline re-run resolves entirely from the cache; GOFLAGS=-mod=mod
#     + GOSUMDB=off keep go.sum verification local (no sum.golang.org round trip).
#
# HARNESS STAGING (netnew §6 Go): pkg/expr ships expr_test.go as `package
# expr_test` (external test pkg, pulls testify) AND a testing.B BenchmarkEval,
# which crashes go-118-fuzz-build's package loader. So we copy pkg/expr's
# NON-test sources + the harness + the KAT probe into a fresh single-package
# dir under a leading-underscore path (skipped by `go build/test ./...`
# wildcards, still loadable by an explicit path) and point the builder there.
# This mirrors cncf-fuzzing's own FuzzExprDecodeString.
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' — must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SRC:=/mayhem}"
: "${CC:=clang}"
: "${CXX:=clang++}"
: "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
export SRC CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS

# Sanitizers (§6.1): the OSS-Fuzz Go path is ASan-only for the libFuzzer link.
# Honor the knob — an explicit empty SANITIZER_FLAGS yields an un-sanitized build.
: "${SANITIZER_FLAGS=-fsanitize=address}"
export SANITIZER_FLAGS
GO_SAN="-fsanitize=address"
[ -n "${SANITIZER_FLAGS}" ] || GO_SAN=""

# Debug-info contract (§6.2 item 10): gc always emits DWARF4 with no knob, so we
# force the clang-compiled cgo C shims to DWARF3 (CGO_CFLAGS/CGO_CXXFLAGS) AND
# prepend a DWARF3 anchor.o at the final clang++ link so the FIRST .debug_info CU
# (what the gate reads) is DWARF < 4. $GO_DEBUG_FLAGS threads any base pins.
export GO_DEBUG_FLAGS="${GO_DEBUG_FLAGS:--gdwarf-3}"
export CGO_CFLAGS="${CGO_CFLAGS:-} ${GO_DEBUG_FLAGS}"
export CGO_CXXFLAGS="${CGO_CXXFLAGS:-} ${GO_DEBUG_FLAGS}"

# Resolve modules offline-first from the in-image cache; network only as fallback.
export GOFLAGS="${GOFLAGS:--mod=mod}"
export GOSUMDB="${GOSUMDB:-off}"
export GOPROXY="${GOPROXY:-file://$(go env GOMODCACHE)/cache/download,https://proxy.golang.org,direct}"

cd "$SRC"
go version

TARGET="fuzz_expr"
STAGE="$SRC/_mayhem_harness/expr"

# ── Stage a clean single-package copy of pkg/expr (non-test sources) ───────────
rm -rf "$STAGE"
mkdir -p "$STAGE"
for f in "$SRC"/pkg/expr/*.go; do
  case "$f" in
    *_test.go) continue ;;   # drop test files (expr_test.go's testify + testing.B trap)
  esac
  cp "$f" "$STAGE/"
done
cp "$SRC/mayhem/harness_expr.go.src" "$STAGE/harness_expr.go"
cp "$SRC/mayhem/kat_expr.go.src"     "$STAGE/kat_expr.go"

# ── Module graph: tidy FIRST, then add the go-118-fuzz-build /testing shim ─────
# (order matters — a trailing `go mod tidy` would prune the shim, netnew §6 Go).
# Reference the shim by the PSEUDO-VERSION the Dockerfile's `go install ...@<commit>`
# already resolved + cached. A raw commit hash forces a proxy.golang.org round trip
# to resolve it — fatal on the air-gapped PATCH re-run; the pseudo-version resolves
# straight from the file cache.
GO118_SHIM_VERSION="v0.0.0-20250520111509-a70c2aa677fa"
go mod tidy
go get "github.com/AdamKorcz/go-118-fuzz-build/testing@${GO118_SHIM_VERSION}"

# ── DWARF3 anchor (FIRST object on every link) + the LSan-off hook ─────────────
B="$SRC/mayhem-build"
mkdir -p "$B"
printf 'int __mayhem_dwarf3_anchor;\n' > "$B/anchor.c"
$CC $GO_DEBUG_FLAGS -c "$B/anchor.c" -o "$B/anchor.o"
# LeakSanitizer off at build time (fleet policy for ASan-linked binaries).
$CC $GO_DEBUG_FLAGS $GO_SAN -c "$SRC/mayhem/lsan_off.c" -o "$B/lsan_off.o"

# One recipe for BOTH binaries: go-118-fuzz-build archive of the staged package
# (same tags/-gcflags/-trimpath/c-archive mode) + the same clang++ ASan+libFuzzer
# link. Only -func differs, so the oracle cannot see a different build flavor.
build_one() { # <-func> <output binary>
  local func="$1" out="$2" name
  name="$(basename "$out")"
  echo "=== go-118-fuzz-build -func $func -> $out ==="
  go-118-fuzz-build -func "$func" -o "$B/$name.a" ./_mayhem_harness/expr
  $CXX $GO_SAN $LIB_FUZZING_ENGINE "$B/anchor.o" "$B/lsan_off.o" "$B/$name.a" -o "$out"
  file "$out" | grep -q 'dynamically linked' \
    || { echo "FATAL: $out is not dynamically linked"; exit 1; }
  echo "built $out"
}

build_one FuzzExprDecodeString "/mayhem/$TARGET"
# KAT oracle: NOT a fuzz target. Dynamically linked, so the gate's LD_PRELOAD
# sabotage shim neuters it (a static `go test` binary would be immune).
build_one FuzzExprKAT /mayhem/expr_kat

echo "build.sh complete"
