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

workspace=$(mktemp -d "/tmp/owndock-dual-agent.XXXXXX")
agent_a_pid=
agent_b_pid=
server_pid=
proxy_a_pid=
proxy_b_pid=
engine_a_id=
engine_b_id=
cleanup() {
	for process in "$agent_a_pid" "$agent_b_pid" "$server_pid" "$proxy_a_pid" "$proxy_b_pid"; do
		if [ -n "$process" ]; then
			kill -TERM "$process" >/dev/null 2>&1 || true
			wait "$process" >/dev/null 2>&1 || true
		fi
	done
	for engine in "$engine_a_id" "$engine_b_id"; do
		if [ -n "$engine" ]; then
			docker rm -f "$engine" >/dev/null 2>&1 || true
		fi
	done
    if [ "${OWNDOCK_KEEP_DUAL_AGENT_FIXTURE:-0}" = 1 ]; then
        printf '%s\n' "Dual Agent fixture retained at $workspace" >&2
    else
        rm -rf "$workspace"
    fi
}
trap cleanup EXIT HUP INT TERM

runtime_mode=${OWNDOCK_DUAL_AGENT_RUNTIME:-0}
case "$runtime_mode" in
	0)
		initial_runtime_probe=expired
		expected_command_status=command_expired
		initial_command_suffix=
		reconnect_command_suffix=
		outage_command_suffix=
		;;
	1)
		initial_runtime_probe=ready
		expected_command_status=runtime_ready
		initial_command_suffix=initial
		reconnect_command_suffix=host-b-reconnect
		outage_command_suffix=host-a-outage
		;;
	*) fail "OWNDOCK_DUAL_AGENT_RUNTIME must be 0 or 1" ;;
esac

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

wait_for_engine() {
	engine=$1
	attempt=0
	while [ "$attempt" -lt 900 ]; do
		if docker exec "$engine" docker --host tcp://127.0.0.1:2375 version \
			>/dev/null 2>&1; then
			return
		fi
		attempt=$((attempt + 1))
		sleep 0.1
	done
	docker logs --tail 80 "$engine" >&2 || true
	fail "timed out waiting for isolated Docker Engine $engine"
}

start_engine() {
	docker run -d --privileged \
		--env DOCKER_TLS_CERTDIR= \
		--publish 127.0.0.1::2375 \
		'docker:29.6.1-dind@sha256:66d292e5c26bd33a6f6f61cacb880de2186339a524ecba1ce098dbbaceed6515' \
		dockerd --host=tcp://0.0.0.0:2375 --tls=false --storage-driver=vfs
}

materials_a=$workspace/materials-a
materials_b=$workspace/materials-b
"$tool" materials --output "$materials_a" --host-id conformance-host-a
"$tool" identity --authority "$materials_a" --output "$materials_b" \
	--host-id conformance-host-b

docker_socket_a=/var/run/docker.sock
docker_socket_b=/var/run/docker.sock
if [ "$runtime_mode" = 1 ]; then
	command -v docker >/dev/null 2>&1 || fail "Docker CLI is required for live runtime mode"
	engine_a_id=$(start_engine)
	engine_b_id=$(start_engine)
	wait_for_engine "$engine_a_id"
	wait_for_engine "$engine_b_id"
	engine_a_address=$(docker port "$engine_a_id" 2375/tcp | sed -n '1p')
	engine_b_address=$(docker port "$engine_b_id" 2375/tcp | sed -n '1p')
	[ -n "$engine_a_address" ] || fail "Host A Docker Engine loopback address is missing"
	[ -n "$engine_b_address" ] || fail "Host B Docker Engine loopback address is missing"
	docker_socket_a=$workspace/docker-a.sock
	docker_socket_b=$workspace/docker-b.sock
	proxy_a_ready=$workspace/proxy-a-ready
	proxy_b_ready=$workspace/proxy-b-ready
	"$tool" docker-proxy --listen "$docker_socket_a" --upstream "$engine_a_address" \
		--ready-file "$proxy_a_ready" >"$workspace/proxy-a.log" 2>&1 &
	proxy_a_pid=$!
	"$tool" docker-proxy --listen "$docker_socket_b" --upstream "$engine_b_address" \
		--ready-file "$proxy_b_ready" >"$workspace/proxy-b.log" 2>&1 &
	proxy_b_pid=$!
	wait_for_file "$proxy_a_ready"
	wait_for_file "$proxy_b_ready"
fi

ready_one=$workspace/ready-one
result_a_one=$workspace/result-a-one
result_b_one=$workspace/result-b-one
"$tool" serve-dual --materials "$materials_a" --ready-file "$ready_one" \
	--result-a "$result_a_one" --result-b "$result_b_one" \
	--runtime-probe "$initial_runtime_probe" \
	--command-suffix "$initial_command_suffix" \
	>"$workspace/server-one.log" 2>&1 &
server_pid=$!
wait_for_file "$ready_one"
endpoint=$(tr -d '\r\n' < "$ready_one")
listen=${endpoint#https://}
listen=${listen%/api/v1/agent/connect}
"$tool" config --output "$materials_a" --endpoint "$endpoint" \
	--host-id conformance-host-a --docker-socket "$docker_socket_a"
"$tool" config --output "$materials_b" --endpoint "$endpoint" \
	--host-id conformance-host-b --docker-socket "$docker_socket_b"

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
grep -qx "command_id=conformance-probe-conformance-host-a${initial_command_suffix:+-$initial_command_suffix}" "$result_a_one" || \
	fail "Host A received another Host's command"
grep -qx "command_id=conformance-probe-conformance-host-b${initial_command_suffix:+-$initial_command_suffix}" "$result_b_one" || \
    fail "Host B received another Host's command"
grep -qx "command_status=$expected_command_status" \
	"$result_a_one" || fail "Host A command result is missing"
grep -qx "command_status=$expected_command_status" \
	"$result_b_one" || fail "Host B command result is missing"

# The same shared endpoint now rejects Host A while accepting Host B. Host A's
# process must remain alive without preventing Host B from reconnecting.
ready_two=$workspace/ready-two
result_b_two=$workspace/result-b-two
"$tool" serve-dual --listen "$listen" --materials "$materials_a" \
	--ready-file "$ready_two" --result-a "$workspace/unused-a-two" \
	--result-b "$result_b_two" --only-host conformance-host-b \
	--runtime-probe "$initial_runtime_probe" \
	--command-suffix "$reconnect_command_suffix" \
    >"$workspace/server-two.log" 2>&1 &
server_pid=$!
wait_for_file "$ready_two"
wait_for_file "$result_b_two"
wait "$server_pid" || fail "Host B did not reconnect while Host A was rejected"
server_pid=
kill -0 "$agent_a_pid" >/dev/null 2>&1 || fail "Host A Agent exited during its partition"
kill -0 "$agent_b_pid" >/dev/null 2>&1 || fail "Host B Agent exited after reconnect"
[ ! -e "$workspace/unused-a-two" ] || fail "partitioned Host A completed a control session"
grep -qx 'managed_host_id=conformance-host-b' "$result_b_two" || fail "Host B reconnected as the wrong Host"
grep -qx "command_id=conformance-probe-conformance-host-b${reconnect_command_suffix:+-$reconnect_command_suffix}" "$result_b_two" || \
	fail "Host B reconnect received another Host's command"

third_runtime_probe=$initial_runtime_probe
if [ "$runtime_mode" = 1 ]; then
	docker stop --time 5 "$engine_a_id" >/dev/null
	third_runtime_probe=unreachable
fi

ready_three=$workspace/ready-three
result_a_three=$workspace/result-a-three
"$tool" serve-dual --listen "$listen" --materials "$materials_a" \
	--ready-file "$ready_three" --result-a "$result_a_three" \
	--result-b "$workspace/unused-b-three" --only-host conformance-host-a \
	--runtime-probe "$third_runtime_probe" \
	--command-suffix "$outage_command_suffix" \
    >"$workspace/server-three.log" 2>&1 &
server_pid=$!
wait_for_file "$ready_three"
wait_for_file "$result_a_three"
wait "$server_pid" || fail "Host A did not recover through the shared endpoint"
server_pid=
grep -qx 'managed_host_id=conformance-host-a' "$result_a_three" || fail "Host A recovered as the wrong Host"
grep -qx "command_id=conformance-probe-conformance-host-a${outage_command_suffix:+-$outage_command_suffix}" "$result_a_three" || \
	fail "Host A recovery received another Host's command"

if [ "$runtime_mode" = 1 ]; then
	grep -qx 'command_status=runtime_unreachable' "$result_a_three" || \
		fail "Host A did not report its isolated Engine outage"
	docker start "$engine_a_id" >/dev/null
	wait_for_engine "$engine_a_id"
	kill -TERM "$proxy_a_pid" >/dev/null 2>&1 || true
	wait "$proxy_a_pid" >/dev/null 2>&1 || true
	proxy_a_pid=
	rm -f "$docker_socket_a"
	engine_a_address=$(docker port "$engine_a_id" 2375/tcp | sed -n '1p')
	[ -n "$engine_a_address" ] || fail "restarted Host A Docker Engine address is missing"
	proxy_a_ready=$workspace/proxy-a-recovery-ready
	"$tool" docker-proxy --listen "$docker_socket_a" --upstream "$engine_a_address" \
		--ready-file "$proxy_a_ready" >"$workspace/proxy-a-recovery.log" 2>&1 &
	proxy_a_pid=$!
	wait_for_file "$proxy_a_ready"
	ready_four=$workspace/ready-four
	result_a_four=$workspace/result-a-four
	"$tool" serve-dual --listen "$listen" --materials "$materials_a" \
		--ready-file "$ready_four" --result-a "$result_a_four" \
		--result-b "$workspace/unused-b-four" --only-host conformance-host-a \
		--runtime-probe ready --command-suffix host-a-recovery \
		>"$workspace/server-four.log" 2>&1 &
	server_pid=$!
	wait_for_file "$ready_four"
	wait_for_file "$result_a_four"
	wait "$server_pid" || fail "Host A runtime did not recover after Engine restart"
	server_pid=
	grep -qx 'managed_host_id=conformance-host-a' "$result_a_four" || \
		fail "Host A runtime recovery crossed routes"
	grep -qx 'command_id=conformance-probe-conformance-host-a-host-a-recovery' "$result_a_four" || \
		fail "Host A runtime recovery received the wrong command"
	grep -qx 'command_status=runtime_ready' "$result_a_four" || \
		fail "Host A runtime did not become ready after Engine restart"
fi

kill -TERM "$agent_a_pid"
wait "$agent_a_pid" || fail "Host A Agent did not stop cleanly"
agent_a_pid=
kill -TERM "$agent_b_pid"
wait "$agent_b_pid" || fail "Host B Agent did not stop cleanly"
agent_b_pid=

if [ "$runtime_mode" = 1 ]; then
	printf '%s\n' "OwnDock dual Agent processes, isolated Engines, routing, outage and recovery passed"
else
	printf '%s\n' "OwnDock shared-control dual Agent routing and single-Host rejection recovery passed"
fi
