#!/usr/bin/env bash
# =====================================================================
# run.sh - SAS OTP end-to-end test: real Keycloak, SAS mock, login with curl
#
#   ci/sas-e2e/run.sh [keycloak-version] [provider-jar]
#
# Starts the SAS mock (SasMockServer from the test classes: real vendor
# crypto, fresh agent key file, accepts OTP 123456) and the official Keycloak
# distribution (Maven Central, or KC_DIST=<unpacked dir>) with the provider
# jar and the Thales JARs, then runs sas_e2e.py. No root, no Docker.
#
# Needs: Java 21+, Python 3, curl, the decrypted Thales JARs in
# THALES_DIR (default thales/lib, see thales/decrypt.sh) and target/test-classes
# (mvn package -DskipTests builds both jar and test classes).
# Defaults: keycloak.version from pom.xml, jar from target/.
#
# Output in $WORK_DIR (default .sas-e2e/): keycloak.log, sas-mock.log, e2e.out
# =====================================================================
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SCRIPT_DIR="$ROOT/ci/sas-e2e"
KC_VERSION="${1:-$(sed -n 's:.*<keycloak.version>\(.*\)</keycloak.version>.*:\1:p' "$ROOT/pom.xml" | head -n 1)}"
JAR="${2:-}"
WORK_DIR="${WORK_DIR:-$ROOT/.sas-e2e}"
THALES_DIR="${THALES_DIR:-$ROOT/thales/lib}"
KC_PORT="${KC_PORT:-18181}"
KC_MGMT_PORT="${KC_MGMT_PORT:-19101}"
MOCK_PORT="${MOCK_PORT:-18999}"
START_TIMEOUT="${START_TIMEOUT:-300}"
MVN="${MVN:-mvn -B -q}"

mkdir -p "$WORK_DIR"
LOG="$WORK_DIR/keycloak.log"
MOCK_LOG="$WORK_DIR/sas-mock.log"
OUT="$WORK_DIR/e2e.out"
KEY_FILE="$WORK_DIR/agent.bsidkey"

for f in commons.jar token-validator-adapter-jar-with-dependencies.jar; do
  [ -f "$THALES_DIR/$f" ] || { echo "[e2e] $THALES_DIR/$f missing - run thales/decrypt.sh"; exit 1; }
done

if [ -z "$JAR" ] || [ ! -d "$ROOT/target/test-classes" ]; then
  JAR="${JAR:-$(ls "$ROOT"/target/keycloak-sas-otp-authenticator-*.jar 2>/dev/null | head -n 1 || true)}"
  if [ -z "$JAR" ] || [ ! -d "$ROOT/target/test-classes" ]; then
    echo "[e2e] building provider jar and test classes"
    (cd "$ROOT" && $MVN -Dkeycloak.version="$KC_VERSION" clean package -DskipTests) || { echo "[e2e] build failed"; exit 1; }
    JAR=$(ls "$ROOT"/target/keycloak-sas-otp-authenticator-*.jar | head -n 1)
  fi
fi
echo "[e2e] jar: $JAR"

if [ -n "${KC_DIST:-}" ]; then
  DIST_DIR="$KC_DIST"
else
  DIST_DIR="$WORK_DIR/dist/keycloak-$KC_VERSION"
  if [ ! -x "$DIST_DIR/bin/kc.sh" ]; then
    mkdir -p "$WORK_DIR/dist"
    $MVN dependency:copy -Dartifact="org.keycloak:keycloak-quarkus-dist:$KC_VERSION:tar.gz" \
      -DoutputDirectory="$WORK_DIR/dist" || { echo "[e2e] Keycloak distribution $KC_VERSION not available"; exit 1; }
    tar -xzf "$WORK_DIR/dist/keycloak-quarkus-dist-$KC_VERSION.tar.gz" -C "$WORK_DIR/dist"
    rm -f "$WORK_DIR/dist/keycloak-quarkus-dist-$KC_VERSION.tar.gz"
  fi
fi

RUN_DIR="$WORK_DIR/run"
rm -rf "$RUN_DIR"
cp -r "$DIST_DIR" "$RUN_DIR"
cp "$JAR" "$THALES_DIR"/commons.jar "$THALES_DIR"/token-validator-adapter-jar-with-dependencies.jar "$RUN_DIR/providers/"

KC_PID=""
MOCK_PID=""
stop_all() {
  for pid in $KC_PID $MOCK_PID; do
    if kill -0 "$pid" 2>/dev/null; then
      kill "$pid" 2>/dev/null
      for _ in $(seq 1 30); do kill -0 "$pid" 2>/dev/null || break; sleep 1; done
      kill -9 "$pid" 2>/dev/null || true
    fi
  done
}
trap stop_all EXIT

# SAS mock with Keycloak's libraries (BouncyCastle, JAXB, commons-lang3) like in production
echo "[e2e] starting SAS mock on port $MOCK_PORT"
rm -f "$KEY_FILE"
java -cp "$ROOT/target/test-classes:$ROOT/target/classes:$THALES_DIR/*:$RUN_DIR/lib/lib/main/*:$RUN_DIR/lib/lib/boot/*" \
  nrw.sit.keycloak.authenticator.sas.SasMockServer "$MOCK_PORT" "$KEY_FILE" > "$MOCK_LOG" 2>&1 &
MOCK_PID=$!
for _ in $(seq 1 30); do grep -q "SAS mock listening" "$MOCK_LOG" 2>/dev/null && break; sleep 1; done
if ! grep -q "SAS mock listening" "$MOCK_LOG"; then
  echo "[e2e] SAS mock did not start:"; cat "$MOCK_LOG"; exit 1
fi
TV_URL="http://127.0.0.1:$MOCK_PORT/TokenValidator/TokenValidator.asmx?orgCode=MOCK"

echo "[e2e] starting Keycloak $KC_VERSION"
KC_BOOTSTRAP_ADMIN_USERNAME=admin KC_BOOTSTRAP_ADMIN_PASSWORD=admin \
  "$RUN_DIR/bin/kc.sh" start-dev \
    --http-port="$KC_PORT" \
    --http-management-port="$KC_MGMT_PORT" \
    --health-enabled=true \
    --log-level=info,nrw.sit.keycloak.authenticator.sas:debug \
    > "$LOG" 2>&1 &
KC_PID=$!

ready=false
for _ in $(seq 1 "$START_TIMEOUT"); do
  kill -0 "$KC_PID" 2>/dev/null || break
  if curl -sf --noproxy '*' "http://localhost:$KC_MGMT_PORT/health/ready" > /dev/null 2>&1; then ready=true; break; fi
  sleep 1
done
if ! $ready; then
  echo "[e2e] Keycloak did not start:"; tail -n 40 "$LOG"; exit 1
fi
echo "[e2e] Keycloak ready"

python3 "$SCRIPT_DIR/sas_e2e.py" "http://localhost:$KC_PORT" "$TV_URL" "$KEY_FILE" "$KEY_FILE" "$MOCK_LOG" 2>&1 | tee "$OUT"
rc=${PIPESTATUS[0]}
stop_all
trap - EXIT

# S7/S8 provoke ERROR lines of the authenticator and the vendor wrapper on purpose;
# anything else is a finding
errors=$(grep -E '^[0-9-]+ [0-9:,.]+ +ERROR ' "$LOG" \
  | grep -vE '\[(nrw\.sit\.keycloak\.authenticator\.sas|com\.safenet\.keycloak\.agent)\.' || true)
if [ -n "$errors" ]; then
  echo "[e2e] unexpected ERROR lines in the Keycloak log:"; printf '%s\n' "$errors" | head -n 20
  rc=1
fi
[ "$rc" -eq 0 ] && echo "[e2e] PASS" || echo "[e2e] FAIL (see $OUT, $LOG, $MOCK_LOG)"
exit "$rc"
