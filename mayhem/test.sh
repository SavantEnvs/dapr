#!/usr/bin/env bash
#
# mayhem/test.sh — BEHAVIORAL oracle for dapr's CEL expression engine
# (pkg/expr: (*Expr).DecodeString / Eval / String / MarshalJSON / UnmarshalJSON).
#
# Every case below is fixed input -> exact expected result, owned by THIS file:
# test.sh writes the input, runs the probe once per case, and compares the
# probe's single result line itself. The probe (/mayhem/expr_kat, built by
# build.sh with the same go-118-fuzz-build command and link line as the graded
# fuzz target) prints only the computed value, never a verdict or a tally.
#
# One process per case: a case that fails, panics or hangs (bounded by
# libFuzzer's own -timeout) costs that case only, so the pass count is graded
# per behavior, not all-or-nothing. The probe is dynamically linked: when the
# program is neutered (LD_PRELOAD _exit(0)) it prints nothing and every case
# fails (§6.3).
#
# Expected values are CEL-spec semantics (arithmetic, strings, lists, maps,
# macros, conversions, runtime errors) plus dapr's own variable discovery in
# DecodeString (undeclared identifiers become dyn variables, over several
# compile rounds when needed) and upstream expr_test.go's TestEval golden case.
# Every function and macro of the standard CEL environment that DecodeString
# builds is called at least once, including on discovered variables, so a
# "fix" that rejects calls outside some allow-list fails cases.
#
# Emits a CTRF summary; exits non-zero iff failed>0.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
cd "${SRC:-/mayhem}"

emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-${SRC:-/mayhem}/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

# ── Cases: <name> | <variables JSON> | <expected probe line> | <CEL expression> ──
# (the expression is the LAST field, so it may contain '|')
CASES=$(cat <<'EOF'
int_add|{}|OK int64 12|7 + 5
int_sub|{}|OK int64 14|20 - 6
int_mul|{}|OK int64 24|3 * 8
int_div_truncates|{}|OK int64 3|17 / 5
int_mod|{}|OK int64 2|17 % 5
int_precedence|{}|OK int64 20|(2 + 3) * 4
int_unary_minus|{}|OK int64 5|-(4 - 9)
double_mul|{}|OK float64 7.5|2.5 * 3.0
uint_add|{}|OK uint64 10|7u + 3u
string_concat|{}|OK string foobar|"foo" + "bar"
string_size|{}|OK int64 5|size("hello")
string_starts_ends|{}|OK bool true|"dapr".startsWith("da") && "dapr".endsWith("pr") && !"dapr".contains("x")
string_matches|{}|OK bool true|"abc123".matches("^[a-z]+[0-9]+$")
compare_chain|{}|OK bool false|1 < 2 && 2 <= 2 && 3 > 2 && 3 >= 4
logic_or_not|{}|OK bool true|!(1 == 2) || false
ternary|{}|OK string yes|2 > 1 ? "yes" : "no"
list_size|{}|OK int64 3|size([1, 2, 3])
list_index|{}|OK int64 2|[1, 2, 3][1]
list_in|{}|OK bool true|'a' in ['a', 'b']
list_concat_size|{}|OK int64 4|size([1, 2] + [3, 4])
map_index|{}|OK int64 42|{"k": 42}["k"]
map_in|{}|OK bool false|"z" in {"a": 1, "b": 2}
macro_filter|{}|OK int64 2|[1, 2, 3, 4].filter(x, x % 2 == 0).size()
macro_all|{}|OK bool true|[1, 2, 3].all(x, x > 0)
macro_exists|{}|OK bool false|[1, 2, 3].exists(x, x == 4)
macro_map|{}|OK int64 6|[1, 2, 3].map(x, x * 2)[2]
convert_int|{}|OK int64 43|int("42") + 1
convert_string|{}|OK string 7x|string(7) + "x"
timestamp_year|{}|OK int64 2020|timestamp("2020-01-01T00:00:00Z").getFullYear()
duration_minutes|{}|OK int64 90|duration("1h30m").getMinutes()
scope_golden_true|{"input":{"test":1234},"result":{"test":5678}}|OK bool true|(has(input.test) && input.test == 1234) || (has(result.test) && result.test == 5678)
scope_golden_false|{"input":{"test":1},"result":{"test":2}}|OK bool false|(has(input.test) && input.test == 1234) || (has(result.test) && result.test == 5678)
vars_three|{"a":1,"b":2,"c":3}|OK int64 7|a + b * c
vars_repeated|{"x":3}|OK int64 12|x * x + x
vars_nested|{"input":{"a":{"b":{"c":"x"}}}}|OK bool true|input.a.b.c == "x"
vars_list|{"input":{"items":[1,2,3]}}|OK int64 4|input.items[0] + input.items[2]
vars_mixed|{"input":{"name":"svc","id":7}}|OK string svc-7|input.name + "-" + string(input.id)
vars_has_missing|{"input":{}}|OK bool false|has(input.missing)
convert_double|{}|OK float64 5|double("2.5") * 2.0
convert_uint|{}|OK uint64 8|uint(7) + 1u
convert_bool|{}|OK bool true|bool("true") && true
convert_bytes_size|{}|OK int64 3|size(bytes("abc"))
type_of_int|{}|OK bool true|type(1) == int
dyn_add|{}|OK int64 5|dyn(2) + 3
macro_exists_one|{}|OK bool true|[1, 2, 3].exists_one(x, x == 2)
timestamp_month|{}|OK int64 2|timestamp("2020-03-15T10:20:30Z").getMonth()
timestamp_day_of_month|{}|OK int64 14|timestamp("2020-03-15T10:20:30Z").getDayOfMonth()
timestamp_date|{}|OK int64 15|timestamp("2020-03-15T10:20:30Z").getDate()
timestamp_day_of_week|{}|OK int64 0|timestamp("2020-03-15T10:20:30Z").getDayOfWeek()
timestamp_day_of_year|{}|OK int64 74|timestamp("2020-03-15T10:20:30Z").getDayOfYear()
timestamp_hours|{}|OK int64 10|timestamp("2020-03-15T10:20:30Z").getHours()
timestamp_seconds|{}|OK int64 30|timestamp("2020-03-15T10:20:30Z").getSeconds()
duration_seconds|{}|OK int64 90|duration("90s").getSeconds()
duration_millis|{}|OK int64 1500|duration("1500ms").getMilliseconds()
timestamp_millis|{}|OK int64 250|timestamp("2020-03-15T10:20:30.250Z").getMilliseconds()
timestamp_minutes|{}|OK int64 20|timestamp("2020-03-15T10:20:30Z").getMinutes()
timestamp_tz_offset|{}|OK int64 15|timestamp("2020-03-15T10:20:30Z").getHours("+05:00")
timestamp_tz_utc|{}|OK int64 0|timestamp("2020-03-15T10:20:30Z").getDayOfWeek("UTC")
timestamp_diff|{}|OK int64 3600|(timestamp("2020-01-01T01:00:00Z") - timestamp("2020-01-01T00:00:00Z")).getSeconds()
timestamp_plus_dur|{}|OK bool true|timestamp("2020-01-01T00:00:00Z") + duration("24h") == timestamp("2020-01-02T00:00:00Z")
timestamp_from_int|{}|OK int64 2001|timestamp(1000000000).getFullYear()
int_from_timestamp|{}|OK int64 86400|int(timestamp("1970-01-02T00:00:00Z"))
duration_hours|{}|OK int64 2|duration("150m").getHours()
string_from_bytes|{}|OK string abc|string(b"abc")
bytes_literal_eq|{}|OK bool true|b"abc" == bytes("abc")
matches_global|{}|OK bool true|matches("dapr-runtime", "^dapr-")
size_method_forms|{}|OK int64 6|"abc".size() + [1, 2].size() + {"a": 1}.size()
macro_map_filter|{}|OK int64 20|[1, 2, 3].map(x, x > 1, x * 10)[0]
null_literal|{}|OK bool true|null == null
type_names|{}|OK bool true|type("a") == string && type(1u) == uint && type([]) == list && type({}) == map && type(null) == null_type && type(int) == type
double_to_int|{}|OK int64 -2|int(-2.7)
double_to_uint|{}|OK uint64 3|uint(3.9)
vars_method_call|{"input":{"name":"svc-a"}}|OK bool true|input.name.startsWith("s") && input.name.endsWith("-a")
vars_func_arg|{"input":{"items":[1,2,3]}}|OK int64 3|size(input.items)
vars_macro|{"input":{"items":[1,2,3,4]}}|OK bool true|input.items.exists(i, i > 3) && input.items.all(i, i > 0)
vars_convert|{"n":"41"}|OK int64 42|int(n) + 1
vars_matches|{"s":"abc"}|OK bool true|s.matches("^a")
vars_cmp_str|{"a":"apple","b":"banana"}|OK bool true|a < b
err_parse_trailing_op|{}|DECODE_ERR|1 +
err_parse_parens|{}|DECODE_ERR|((((
err_parse_unterminated|{}|DECODE_ERR|"abc
err_parse_empty|{}|DECODE_ERR|
err_type_mismatch|{}|DECODE_ERR|1 + "a"
err_eval_div_zero|{}|EVAL_ERR|1 / 0
err_eval_index|{}|EVAL_ERR|[1, 2][5]
err_eval_overflow|{}|EVAL_ERR|9223372036854775807 + 1
err_eval_convert|{}|EVAL_ERR|int("abc")
err_eval_unbound_var|{}|EVAL_ERR|missing_var + 1
EOF
)

# Multi-round variable discovery: cel-go reports at most 100 issues per compile,
# so 105 distinct free variables need a second declare-and-recompile round in
# DecodeString. Expected: 1 + 2 + ... + 105 = 5565.
mr_vars=""; mr_expr=""
for k in $(seq 1 105); do
  mr_vars+="${mr_vars:+,}\"v$k\":$k"; mr_expr+="${mr_expr:+ + }v$k"
done
CASES+=$'\n'"vars_105_multi_round|{$mr_vars}|OK int64 5565|$mr_expr"

PROBE=/mayhem/expr_kat
passed=0; failed=0

# Unconditional: a missing probe is a build.sh bug — every case FAILS, never skips.
if [ ! -x "$PROBE" ]; then
  n=$(printf '%s\n' "$CASES" | grep -c '|')
  echo "FAIL: KAT probe $PROBE missing or not executable (build.sh should have produced it)" >&2
  emit_ctrf "dapr-expr-kat" 0 "$n"
  exit 1
fi

WORK="$(mktemp -d "${TMPDIR:-/tmp}/dapr-expr-kat.XXXXXX")" || { echo "FAIL: mktemp" >&2; exit 1; }
trap 'rm -rf "$WORK"' EXIT

# Probe input = the shim's string encoding: 4-byte big-endian length, then the
# payload "<variables JSON>\n<expression>".
encode_case() { # <payload> <file>
  local n
  n=$(printf '%s' "$1" | LC_ALL=C wc -c)
  printf "$(printf '\\%03o\\%03o\\%03o\\%03o' $(( (n >> 24) & 255 )) $(( (n >> 16) & 255 )) $(( (n >> 8) & 255 )) $(( n & 255 )))" > "$2"
  printf '%s' "$1" >> "$2"
}

i=0
while IFS='|' read -r name vars want code; do
  [ -n "$name" ] || continue
  i=$((i + 1))
  f="$WORK/case_$i"
  encode_case "$vars"$'\n'"$code" "$f"
  # -detect_leaks=0: libFuzzer otherwise RE-RUNS an input whose run did more
  # mallocs than frees (its leak heuristic; the Go runtime trips it at random),
  # which would print the result twice.
  got="$("$PROBE" -detect_leaks=0 -timeout=30 "$f" 2>"$WORK/err_$i")"; rc=$?
  if [ "$rc" -eq 0 ] && [ "$got" = "$want" ]; then
    echo "PASS: $name"; passed=$((passed + 1))
  else
    echo "FAIL: $name (expr: $code) expected '$want', got '$got' (rc=$rc)"; failed=$((failed + 1))
  fi
done <<< "$CASES"

emit_ctrf "dapr-expr-kat" "$passed" "$failed"
