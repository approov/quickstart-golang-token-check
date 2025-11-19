#!/usr/bin/env bash
set -Eeu pipefail

need_cmd() { command -v "$1" >/dev/null 2>&1 || { echo "Missing command: $1"; exit 1; }; }
need_cmd approov
need_cmd curl

BASE_URL="${BASE_URL:-http://localhost:8111}"
CONFIGDIR="${CONFIGDIR:-./config}"
TOKDIR="$CONFIGDIR/tokens"
LOGDIR="$CONFIGDIR/logs"
HDR_NAME="approov-token"

mkdir -p "$TOKDIR" "$LOGDIR"
LOGFILE="$LOGDIR/$(date '+%Y-%m-%d_%H-%M-%S').log"

# show Approov API domains
# Check Approov CLI authentication
if ! approov api -list >/dev/null 2>&1; then
  echo "ERROR: Approov CLI is not authenticated. Please authenticate before running tests."
  exit 1
fi

# Approov state check
echo "Approov state:"
state_json=$(curl -s "$BASE_URL/approov-state")
if echo "$state_json" | grep -q '"state":"disabled"'; then
  echo "Approov service: DISABLED"
  approov_disabled=true
else
  echo "Approov service: ENABLED"
  approov_disabled=false
fi


test_results=()
run_test() {
  local name="$1"; shift
  local expected="$1"; shift
  local resp status
  resp=$(curl -i -s "$@")
  status=$(echo "$resp" | grep -m1 HTTP | awk '{print $2}')
  local result
  if [ "$status" = "$expected" ]; then result="Passed"; else result="Failed"; fi
  echo "$name: $result  (status : $status, expected: $expected)"
  test_results+=("$name: $result")
  {
    echo "===== $name ====="
    echo "$resp"
    if [ "$approov_disabled" = true ]; then
      echo "Approov State: disabled, no checks performed."
    else
      echo "Approov State: enabled, token checks performed."
    fi
    echo
  } >> "$LOGFILE" 2>&1
}

have_tokens=true
gen_token() {
  local outfile="$1"; shift
  set +e
  approov token "$@" > "$outfile"
  local rc=$?
  set -e
  if [ $rc -ne 0 ]; then
    echo "Approov CLI failed to generate token for: approov token $*"
    have_tokens=false
    return 1
  fi
  return 0
}

skip_test() {
  local name="$1"
  echo "$name: Skipped"
  test_results+=("$name: Skipped")
  {
    echo "===== $name ====="
    echo "Skipped (token generation unavailable)."
    echo
  } >> "$LOGFILE" 2>&1
}

# 0) Unprotected endpoint
run_test "Unprotected" 200 "$BASE_URL/unprotected"

# If Approov service is disabled, we still try protected endpoints
# but expected codes differ (mainly 200 instead of 401).

# 1) Token check
if $have_tokens; then
  gen_token "$TOKDIR/approov_token_1_valid" -genExample example.com || true
else
  true
fi

if ! $have_tokens; then
  skip_test "Token check (valid)"
  skip_test "Token check (invalid)"
else
  # 1.1 Valid Token
  # If service disabled, most servers still return 200
  expected_status=200
  run_test "Token check (valid)" "$expected_status" \
    -H "$HDR_NAME: $(cat "$TOKDIR/approov_token_1_valid")" \
    "$BASE_URL/token"

  # 1.2 Invalid Token
  gen_token "$TOKDIR/approov_token_1_invalid" -genExample example.com -type invalid || true
  if [ "$approov_disabled" = true ]; then expected_status=200; else expected_status=401; fi
  run_test "Token check (invalid)" "$expected_status" \
    -H "$HDR_NAME: $(cat "$TOKDIR/approov_token_1_invalid")" \
    "$BASE_URL/token"
fi

# 2) Token Binding ["Authorization"]
AUTH_VAL="ExampleAuthToken=="
export HASH_INPUT="$AUTH_VAL"

if $have_tokens; then
  gen_token "$TOKDIR/approov_token_2_valid" -setDataHashInToken "$HASH_INPUT" -genExample example.com || true
fi

if ! $have_tokens; then
  skip_test "Token Binding (valid)"
  skip_test "Token Binding (missing header)"
  skip_test "Token Binding (incorrect header)"
  skip_test "Token Binding (invalid token)"
else
  # 2.1 Valid Token
  expected_status=200
  run_test "Token Binding (valid)" "$expected_status" \
    -H "Authorization: $AUTH_VAL" \
    -H "$HDR_NAME: $(cat "$TOKDIR/approov_token_2_valid")" \
    "$BASE_URL/token-binding-1"

  # 2.2 Missing Header
  if [ "$approov_disabled" = true ]; then expected_status=200; else expected_status=401; fi
  run_test "Token Binding (missing header)" "$expected_status" \
    -H "$HDR_NAME: $(cat "$TOKDIR/approov_token_2_valid")" \
    "$BASE_URL/token-binding-1"

  # 2.3 Incorrect Header
  if [ "$approov_disabled" = true ]; then expected_status=200; else expected_status=401; fi
  run_test "Token Binding (incorrect header)" "$expected_status" \
    -H "Authorization: BadAuthToken==" \
    -H "$HDR_NAME: $(cat "$TOKDIR/approov_token_2_valid")" \
    "$BASE_URL/token-binding-1"

  # 2.4 Invalid Token
  gen_token "$TOKDIR/approov_token_2_invalid" -setDataHashInToken "$HASH_INPUT" -genExample example.com -type invalid || true
  if [ "$approov_disabled" = true ]; then expected_status=200; else expected_status=401; fi
  run_test "Token Binding (invalid token)" "$expected_status" \
    -H "Authorization: $AUTH_VAL" \
    -H "$HDR_NAME: $(cat "$TOKDIR/approov_token_2_invalid")" \
    "$BASE_URL/token-binding-1"
fi

# 3) Token Binding "Authorization","Content-Digest"
AUTH_VAL2="ExampleAuthToken=="
CD_VAL="ContentDigest=="
export HASH_INPUT="${AUTH_VAL2}${CD_VAL}"

if $have_tokens; then
  gen_token "$TOKDIR/approov_token_3_valid" -setDataHashInToken "$HASH_INPUT" -genExample example.com || true
fi

if ! $have_tokens; then
  skip_test "Token Binding 2 (valid)"
  skip_test "Token Binding 2 (missing header)"
  skip_test "Token Binding 2 (incorrect header)"
  skip_test "Token Binding 2 (invalid token)"
else
  # 3.1 Valid
  expected_status=200
  run_test "Token Binding 2 (valid)" "$expected_status" \
    -H "Authorization: $AUTH_VAL2" \
    -H "Content-Digest: $CD_VAL" \
    -H "$HDR_NAME: $(cat "$TOKDIR/approov_token_3_valid")" \
    "$BASE_URL/token-binding-2"

  # 3.2 Missing headers
  if [ "$approov_disabled" = true ]; then expected_status=200; else expected_status=401; fi
  run_test "Token Binding 2 (missing header)" "$expected_status" \
    -H "$HDR_NAME: $(cat "$TOKDIR/approov_token_3_valid")" \
    "$BASE_URL/token-binding-2"

  # 3.3 Incorrect headers
  if [ "$approov_disabled" = true ]; then expected_status=200; else expected_status=401; fi
  run_test "Token Binding 2 (incorrect header)" "$expected_status" \
    -H "Authorization: BadAuthToken==" \
    -H "Content-Digest: BadContentDigest==" \
    -H "$HDR_NAME: $(cat "$TOKDIR/approov_token_3_valid")" \
    "$BASE_URL/token-binding-2"

  # 3.4 Invalid token
  gen_token "$TOKDIR/approov_token_3_invalid" -setDataHashInToken "$HASH_INPUT" -genExample example.com -type invalid || true
  if [ "$approov_disabled" = true ]; then expected_status=200; else expected_status=401; fi
  run_test "Token Binding 2 (invalid token)" "$expected_status" \
    -H "Authorization: $AUTH_VAL2" \
    -H "Content-Digest: $CD_VAL" \
    -H "$HDR_NAME: $(cat "$TOKDIR/approov_token_3_invalid")" \
    "$BASE_URL/token-binding-2"
fi

echo
echo "Full request and response details are saved in: $LOGFILE"
# echo "Summary:"
# printf ' - %s\n' "${test_results[@]}"