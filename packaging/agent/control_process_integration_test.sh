#!/bin/sh
set -eu

fail() {
    printf '%s\n' "Agent control process conformance failed: $1" >&2
    exit 1
}

[ "$#" -eq 3 ] || fail "usage: control_process_integration_test.sh AGENT CONFIG_TOOL SERVER_TOOL"
agent=$1
config_tool=$2
server_tool=$3
for executable in "$agent" "$config_tool" "$server_tool"; do
    [ -f "$executable" ] && [ ! -L "$executable" ] && [ -x "$executable" ] || \
        fail "all inputs must be executable regular files"
done

workspace=$(mktemp -d "${TMPDIR:-/tmp}/owndock-agent-control.XXXXXX")
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

materials=$workspace/materials
"$config_tool" materials --output "$materials"

wait_for_file() {
    path=$1
    attempt=0
    while [ "$attempt" -lt 100 ]; do
        [ -s "$path" ] && return
        attempt=$((attempt + 1))
        sleep 0.1
    done
    fail "timed out waiting for $path"
}

ready_one=$workspace/ready-one
result_one=$workspace/result-one
"$server_tool" serve \
    --materials "$materials" \
    --ready-file "$ready_one" \
    --result-file "$result_one" \
    > "$workspace/server-one.log" 2>&1 &
server_pid=$!
wait_for_file "$ready_one"
endpoint=$(tr -d '\r\n' < "$ready_one")
"$config_tool" config --output "$materials" --endpoint "$endpoint"

"$agent" -conf "$materials/agent.yaml" > "$workspace/agent.log" 2>&1 &
agent_pid=$!
wait_for_file "$result_one"
wait "$server_pid" || fail "first conformance server failed"
server_pid=
grep -qx 'protocol_version=v1' "$result_one" || fail "first handshake did not negotiate v1"
grep -qx 'status=passed' "$result_one" || fail "first handshake did not pass"

listen=${endpoint#https://}
listen=${listen%/api/v1/agent/connect}
ready_two=$workspace/ready-two
result_two=$workspace/result-two
"$server_tool" serve \
    --listen "$listen" \
    --materials "$materials" \
    --ready-file "$ready_two" \
    --result-file "$result_two" \
    > "$workspace/server-two.log" 2>&1 &
server_pid=$!
wait_for_file "$ready_two"
wait_for_file "$result_two"
wait "$server_pid" || fail "restarted conformance server failed"
server_pid=
grep -qx 'protocol_version=v1' "$result_two" || fail "reconnect did not negotiate v1"
grep -qx 'status=passed' "$result_two" || fail "reconnect did not pass"

kill -TERM "$agent_pid"
wait "$agent_pid" || fail "Agent did not stop cleanly"
agent_pid=
printf '%s\n' "OwnDock Agent external mTLS control and reconnect conformance passed"
