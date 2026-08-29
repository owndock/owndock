#!/bin/sh
set -eu

fail() {
    printf '%s\n' "Dual Agent control process integration failed: $1" >&2
    exit 1
}

[ "$#" -eq 2 ] || fail "usage: dual_control_process_integration_test.sh AGENT CONFORMANCE_TOOL"
agent=$1
tool=$2
for executable in "$agent" "$tool"; do
    [ -f "$executable" ] && [ ! -L "$executable" ] && [ -x "$executable" ] || \
        fail "inputs must be executable regular files"
done

workspace=$(mktemp -d "${TMPDIR:-/tmp}/owndock-dual-agent.XXXXXX")
agent_a_pid=
agent_b_pid=
server_pid=
cleanup() {
    for process in "$agent_a_pid" "$agent_b_pid" "$server_pid"; do
        if [ -n "$process" ]; then
            kill -TERM "$process" >/dev/null 2>&1 || true
            wait "$process" >/dev/null 2>&1 || true
        fi
    done
    if [ "${OWNDOCK_KEEP_DUAL_AGENT_FIXTURE:-0}" = 1 ]; then
        printf '%s\n' "Dual Agent fixture retained at $workspace" >&2
    else
        rm -rf "$workspace"
    fi
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

materials_a=$workspace/materials-a
materials_b=$workspace/materials-b
"$tool" materials --output "$materials_a" --host-id conformance-host-a
"$tool" identity --authority "$materials_a" --output "$materials_b" \
    --host-id conformance-host-b

ready_one=$workspace/ready-one
result_a_one=$workspace/result-a-one
result_b_one=$workspace/result-b-one
"$tool" serve-dual --materials "$materials_a" --ready-file "$ready_one" \
    --result-a "$result_a_one" --result-b "$result_b_one" \
    >"$workspace/server-one.log" 2>&1 &
server_pid=$!
wait_for_file "$ready_one"
endpoint=$(tr -d '\r\n' < "$ready_one")
listen=${endpoint#https://}
listen=${listen%/api/v1/agent/connect}
"$tool" config --output "$materials_a" --endpoint "$endpoint" --host-id conformance-host-a
"$tool" config --output "$materials_b" --endpoint "$endpoint" --host-id conformance-host-b

"$agent" -conf "$materials_a/agent.yaml" >"$workspace/agent-a.log" 2>&1 &
agent_a_pid=$!
"$agent" -conf "$materials_b/agent.yaml" >"$workspace/agent-b.log" 2>&1 &
agent_b_pid=$!
wait_for_file "$result_a_one"
wait_for_file "$result_b_one"
wait "$server_pid" || fail "shared control server failed the initial dual handshake"
server_pid=
grep -qx 'managed_host_id=conformance-host-a' "$result_a_one" || fail "Host A identity crossed routes"
grep -qx 'managed_host_id=conformance-host-b' "$result_b_one" || fail "Host B identity crossed routes"

# The same shared endpoint now rejects Host A while accepting Host B. Host A's
# process must remain alive without preventing Host B from reconnecting.
ready_two=$workspace/ready-two
result_b_two=$workspace/result-b-two
"$tool" serve-dual --listen "$listen" --materials "$materials_a" \
    --ready-file "$ready_two" --result-a "$workspace/unused-a-two" \
    --result-b "$result_b_two" --only-host conformance-host-b \
    >"$workspace/server-two.log" 2>&1 &
server_pid=$!
wait_for_file "$ready_two"
wait_for_file "$result_b_two"
wait "$server_pid" || fail "Host B did not reconnect while Host A was rejected"
server_pid=
kill -0 "$agent_a_pid" >/dev/null 2>&1 || fail "Host A Agent exited during its partition"
kill -0 "$agent_b_pid" >/dev/null 2>&1 || fail "Host B Agent exited after reconnect"
grep -qx 'managed_host_id=conformance-host-b' "$result_b_two" || fail "Host B reconnected as the wrong Host"

ready_three=$workspace/ready-three
result_a_three=$workspace/result-a-three
"$tool" serve-dual --listen "$listen" --materials "$materials_a" \
    --ready-file "$ready_three" --result-a "$result_a_three" \
    --result-b "$workspace/unused-b-three" --only-host conformance-host-a \
    >"$workspace/server-three.log" 2>&1 &
server_pid=$!
wait_for_file "$ready_three"
wait_for_file "$result_a_three"
wait "$server_pid" || fail "Host A did not recover through the shared endpoint"
server_pid=
grep -qx 'managed_host_id=conformance-host-a' "$result_a_three" || fail "Host A recovered as the wrong Host"

kill -TERM "$agent_a_pid"
wait "$agent_a_pid" || fail "Host A Agent did not stop cleanly"
agent_a_pid=
kill -TERM "$agent_b_pid"
wait "$agent_b_pid" || fail "Host B Agent did not stop cleanly"
agent_b_pid=

printf '%s\n' "OwnDock shared-control dual Agent routing and single-Host rejection recovery passed"
