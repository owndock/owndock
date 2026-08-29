#!/bin/sh
set -eu

fail() {
    printf '%s\n' "Agent certificate rotation process integration failed: $1" >&2
    exit 1
}

[ "$#" -eq 2 ] || fail "usage: rotation_process_integration_test.sh AGENT CONFORMANCE_TOOL"
agent=$1
tool=$2
for executable in "$agent" "$tool"; do
    [ -f "$executable" ] && [ ! -L "$executable" ] && [ -x "$executable" ] || \
        fail "inputs must be executable regular files"
done

workspace=$(mktemp -d "${TMPDIR:-/tmp}/owndock-agent-rotation.XXXXXX")
agent_pid=
server_pid=
cleanup() {
    if [ -n "$agent_pid" ]; then
        kill -TERM "$agent_pid" >/dev/null 2>&1 || true
        wait "$agent_pid" >/dev/null 2>&1 || true
    fi
    if [ -n "$server_pid" ]; then
        kill -TERM "$server_pid" >/dev/null 2>&1 || true
        wait "$server_pid" >/dev/null 2>&1 || true
    fi
    rm -rf "$workspace"
}
trap cleanup EXIT HUP INT TERM

wait_for_file() {
    path=$1
    attempt=0
    while [ "$attempt" -lt 150 ]; do
        [ -s "$path" ] && return
        attempt=$((attempt + 1))
        sleep 0.1
    done
    fail "timed out waiting for $path"
}

wait_for_absence() {
    path=$1
    attempt=0
    while [ "$attempt" -lt 100 ]; do
        [ ! -e "$path" ] && [ ! -L "$path" ] && return
        attempt=$((attempt + 1))
        sleep 0.1
    done
    fail "timed out waiting for removal of $path"
}

materials=$workspace/materials
"$tool" materials --output "$materials"
cp "$materials/client-identity.pem" "$workspace/initial-identity.pem"

drop_ready=$workspace/drop-ready
first_request=$workspace/first-request.json
"$tool" rotation-serve \
    --materials "$materials" --ready-file "$drop_ready" \
    --request-file "$first_request" --mode drop \
    >"$workspace/drop-server.log" 2>&1 &
server_pid=$!
wait_for_file "$drop_ready"
endpoint=$(tr -d '\r\n' < "$drop_ready")
listen=${endpoint#https://}
listen=${listen%/api/v1/agent/connect}
case "$listen" in
    127.0.0.1:*) ;;
    *) fail "rotation fixture returned a non-loopback endpoint" ;;
esac
"$tool" config --output "$materials" --endpoint "$endpoint" --enable-rotation

"$agent" -conf "$materials/agent.yaml" >"$workspace/first-agent.log" 2>&1 &
agent_pid=$!
wait_for_file "$first_request"
wait "$server_pid" || fail "response-loss rotation server failed"
server_pid=
kill -TERM "$agent_pid"
wait "$agent_pid" || fail "Agent did not stop after interrupted rotation"
agent_pid=
pending=$materials/client-identity.pem.rotation-pending
[ -f "$pending" ] && [ ! -L "$pending" ] || fail "rotation request was not persisted"
pending_mode=$(stat -f %Lp "$pending" 2>/dev/null || stat -c %a "$pending")
[ "$pending_mode" = 600 ] || fail "pending rotation mode is not 0600"
grep -Fq '"rotation_id"' "$first_request" || fail "rotation request has no ID"
grep -Fq 'CERTIFICATE REQUEST' "$first_request" || fail "rotation request has no CSR"
if grep -Fq 'PRIVATE KEY' "$first_request" "$workspace/first-agent.log" "$workspace/drop-server.log"; then
    fail "rotation private key leaked into request or logs"
fi

respond_ready=$workspace/respond-ready
second_request=$workspace/second-request.json
"$tool" rotation-serve \
    --listen "$listen" --materials "$materials" --ready-file "$respond_ready" \
    --request-file "$second_request" --expected-request-file "$first_request" \
    --mode respond >"$workspace/respond-server.log" 2>&1 &
server_pid=$!
wait_for_file "$respond_ready"
"$agent" -conf "$materials/agent.yaml" >"$workspace/second-agent.log" 2>&1 &
agent_pid=$!
wait "$server_pid" || fail "rotation recovery server failed"
server_pid=
wait_for_absence "$pending"
cmp -s "$first_request" "$second_request" || fail "recovery changed rotation ID or CSR"
if cmp -s "$workspace/initial-identity.pem" "$materials/client-identity.pem"; then
    fail "rotation did not replace the identity bundle"
fi

control_ready=$workspace/control-ready
control_result=$workspace/control-result
"$tool" serve \
    --listen "$listen" --materials "$materials" --ready-file "$control_ready" \
    --result-file "$control_result" --expected-client-serial 4 \
    >"$workspace/control-server.log" 2>&1 &
server_pid=$!
wait_for_file "$control_ready"
wait_for_file "$control_result"
wait "$server_pid" || fail "post-rotation control server failed"
server_pid=
grep -qx 'certificate_serial=4' "$control_result" || \
    fail "post-rotation hello did not use the new certificate"
grep -qx 'status=passed' "$control_result" || fail "post-rotation control handshake failed"

kill -TERM "$agent_pid"
wait "$agent_pid" || fail "Agent did not stop cleanly after rotation"
agent_pid=
if grep -Fq 'PRIVATE KEY' "$workspace"/*.log; then
    fail "rotation private key leaked into process logs"
fi

printf '%s\n' "OwnDock Agent certificate rotation loss, restart, and new-identity handshake passed"
