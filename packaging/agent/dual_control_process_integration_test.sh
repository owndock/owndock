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
		deployment_capabilities=false
		inventory_capabilities=false
		terminal_capabilities=false
		;;
	1)
		initial_runtime_probe=ready
		expected_command_status=runtime_ready
		initial_command_suffix=initial
		reconnect_command_suffix='host-b-reconnect'
		outage_command_suffix='host-a-outage'
		deployment_capabilities=true
		inventory_capabilities=true
		terminal_capabilities=true
		;;
	*) fail "OWNDOCK_DUAL_AGENT_RUNTIME must be 0 or 1" ;;
esac

wait_for_file() {
    path=$1
	limit=${2:-150}
    attempt=0
    while [ "$attempt" -lt "$limit" ]; do
        [ -s "$path" ] && return
		if [ -n "$server_pid" ] && ! kill -0 "$server_pid" >/dev/null 2>&1; then
			fail "process stopped before writing $path"
		fi
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

run_dual_deployment_phase() {
	deployment_kind=$1
	deployment_operation=${deployment_kind#deployment.}
	phase_ready=$workspace/deployment-$deployment_operation-ready
	phase_result_a=$workspace/deployment-$deployment_operation-result-a
	phase_result_b=$workspace/deployment-$deployment_operation-result-b
	"$tool" serve-dual --listen "$listen" --materials "$materials_a" \
		--ready-file "$phase_ready" --result-a "$phase_result_a" \
		--result-b "$phase_result_b" --runtime-probe ready \
		--deployment-capabilities=true --deployment-command "$deployment_kind" \
		--terminal-capabilities=true \
		--inventory-capabilities=true \
		--deployment-container "$deployment_container" --command-suffix dual-runtime \
		--timeout 4m >"$workspace/deployment-$deployment_operation-server.log" 2>&1 &
	server_pid=$!
	wait_for_file "$phase_ready"
	wait_for_file "$phase_result_a" 2100
	wait_for_file "$phase_result_b" 2100
	wait "$server_pid" || fail "dual Agent $deployment_kind phase failed"
	server_pid=
	for host in a b; do
		case "$host" in
			a) phase_result=$phase_result_a ;;
			b) phase_result=$phase_result_b ;;
		esac
		grep -qx "managed_host_id=conformance-host-$host" "$phase_result" || \
			fail "deployment $deployment_operation crossed Host $host identity"
		grep -qx "command_id=conformance-deployment-$deployment_operation-conformance-host-$host-dual-runtime" \
			"$phase_result" || fail "deployment $deployment_operation reached the wrong Host"
		grep -qx 'command_status=deployment_succeeded' "$phase_result" || \
			fail "deployment $deployment_operation did not succeed on Host $host"
	done
}

run_host_deployment_phase() {
	host=$1
	deployment_kind=$2
	sequence=$3
	expected_result=$4
	command_suffix=$5
	deployment_operation=${deployment_kind#deployment.}
	phase_name=$host-$deployment_operation-$sequence-$expected_result
	phase_ready=$workspace/deployment-$phase_name-ready
	phase_result=$workspace/deployment-$phase_name-result
	case "$host" in
		a) unused_result=$workspace/deployment-$phase_name-unused-b ;;
		b) unused_result=$workspace/deployment-$phase_name-unused-a ;;
		*) fail "single-Host deployment phase has an invalid Host" ;;
	esac
	if [ "$host" = a ]; then
		result_a=$phase_result
		result_b=$unused_result
		only_host=conformance-host-a
	else
		result_a=$unused_result
		result_b=$phase_result
		only_host=conformance-host-b
	fi
	"$tool" serve-dual --listen "$listen" --materials "$materials_a" \
		--ready-file "$phase_ready" --result-a "$result_a" --result-b "$result_b" \
		--only-host "$only_host" --runtime-probe ready \
		--deployment-capabilities=true --inventory-capabilities=true \
		--terminal-capabilities=true \
		--deployment-command "$deployment_kind" --deployment-container "$deployment_container" \
		--deployment-sequence "$sequence" --deployment-result "$expected_result" \
		--command-suffix "$command_suffix" --timeout 4m \
		>"$workspace/deployment-$phase_name-server.log" 2>&1 &
	server_pid=$!
	wait_for_file "$phase_ready"
	wait_for_file "$phase_result" 2100
	wait "$server_pid" || fail "Host $host Agent $deployment_kind sequence $sequence phase failed"
	server_pid=
	[ ! -e "$unused_result" ] || fail "deployment phase $phase_name crossed Host identity"
	grep -qx "managed_host_id=$only_host" "$phase_result" || \
		fail "deployment phase $phase_name reached the wrong Host"
	grep -qx "command_id=conformance-deployment-$deployment_operation-$only_host-$command_suffix" \
		"$phase_result" || fail "deployment phase $phase_name returned the wrong command"
	case "$expected_result" in
		succeeded) expected_status=deployment_succeeded ;;
		stale_execution) expected_status=deployment_stale_execution ;;
		*) fail "single-Host deployment phase has an invalid expected result" ;;
	esac
	grep -qx "command_status=$expected_status" "$phase_result" || \
		fail "deployment phase $phase_name returned the wrong status"
}

run_dual_inventory_phase() {
	inventory_kind=$1
	inventory_operation=${inventory_kind#runtime.inventory.}
	phase_ready=$workspace/inventory-$inventory_operation-ready
	phase_result_a=$workspace/inventory-$inventory_operation-result-a
	phase_result_b=$workspace/inventory-$inventory_operation-result-b
	"$tool" serve-dual --listen "$listen" --materials "$materials_a" \
		--ready-file "$phase_ready" --result-a "$phase_result_a" \
		--result-b "$phase_result_b" --runtime-probe ready \
		--deployment-capabilities=true --inventory-capabilities=true \
		--terminal-capabilities=true \
		--inventory-command "$inventory_kind" --deployment-container "$deployment_container" \
		--command-suffix dual-runtime --timeout 4m \
		>"$workspace/inventory-$inventory_operation-server.log" 2>&1 &
	server_pid=$!
	wait_for_file "$phase_ready"
	wait_for_file "$phase_result_a" 2100
	wait_for_file "$phase_result_b" 2100
	wait "$server_pid" || fail "dual Agent $inventory_kind phase failed"
	server_pid=
	for host in a b; do
		case "$host" in
			a) phase_result=$phase_result_a ;;
			b) phase_result=$phase_result_b ;;
		esac
		grep -qx "managed_host_id=conformance-host-$host" "$phase_result" || \
			fail "inventory $inventory_operation crossed Host $host identity"
		grep -qx "command_id=conformance-inventory-$inventory_operation-conformance-host-$host-dual-runtime" \
			"$phase_result" || fail "inventory $inventory_operation reached the wrong Host"
		grep -qx 'command_status=inventory_succeeded' "$phase_result" || \
			fail "inventory $inventory_operation did not succeed on Host $host"
		if [ "$inventory_operation" = prepare ]; then
			grep -qx 'inventory_expected_chunks=1' "$phase_result" || \
				fail "inventory prepare was not a one-chunk bounded snapshot on Host $host"
		elif [ "$inventory_operation" = chunk ]; then
			grep -qx "inventory_deployment_id=conformance-deployment-conformance-host-$host" \
				"$phase_result" || fail "inventory chunk crossed Host $host ownership"
		fi
	done
}

run_dual_inventory_event_phase() {
	expected_truncated=${1:-false}
	command_suffix=${2:-dual-runtime}
	event_since_a=${3:-}
	event_since_b=${4:-}
	phase_ready=$workspace/inventory-events-$command_suffix-ready
	phase_result_a=$workspace/inventory-events-$command_suffix-result-a
	phase_result_b=$workspace/inventory-events-$command_suffix-result-b
	"$tool" serve-dual --listen "$listen" --materials "$materials_a" \
		--ready-file "$phase_ready" --result-a "$phase_result_a" \
		--result-b "$phase_result_b" --runtime-probe ready \
		--deployment-capabilities=true --inventory-capabilities=true \
		--terminal-capabilities=true \
		--inventory-command runtime.inventory.events \
		--inventory-event-id-a "$event_id_a" --inventory-event-id-b "$event_id_b" \
		--inventory-event-since-a "$event_since_a" \
		--inventory-event-since-b "$event_since_b" \
		--inventory-events-truncated="$expected_truncated" \
		--command-suffix "$command_suffix" --timeout 4m \
		>"$workspace/inventory-events-$command_suffix-server.log" 2>&1 &
	server_pid=$!
	wait_for_file "$phase_ready"
	wait_for_file "$phase_result_a" 2100
	wait_for_file "$phase_result_b" 2100
	wait "$server_pid" || fail "dual Agent runtime.inventory.events phase failed"
	server_pid=
	for host in a b; do
		case "$host" in
			a)
				phase_result=$phase_result_a
				expected_event_id=$event_id_a
				forbidden_event_id=$event_id_b
				;;
			b)
				phase_result=$phase_result_b
				expected_event_id=$event_id_b
				forbidden_event_id=$event_id_a
				;;
		esac
		grep -qx "managed_host_id=conformance-host-$host" "$phase_result" || \
			fail "inventory events crossed Host $host identity"
		grep -qx "command_id=conformance-inventory-events-conformance-host-$host-$command_suffix" \
			"$phase_result" || fail "inventory events reached the wrong Host"
		grep -qx 'command_status=inventory_succeeded' "$phase_result" || \
			fail "inventory events did not succeed on Host $host"
		grep -qx "inventory_event_runtime_id=$expected_event_id" "$phase_result" || \
			fail "inventory events omitted Host $host expected Runtime ID"
		event_occurred_at=$(sed -n 's/^inventory_event_occurred_at=//p' "$phase_result")
		[ -n "$event_occurred_at" ] || \
			fail "inventory events omitted Host $host Docker-owned cursor"
		case "$host" in
			a)
				event_cursor_a=$event_occurred_at
				expected_since=$event_since_a
				;;
			b)
				event_cursor_b=$event_occurred_at
				expected_since=$event_since_b
				;;
		esac
		if [ -n "$expected_since" ] && [ "$event_occurred_at" != "$expected_since" ]; then
			fail "inventory events did not inclusively replay Host $host cursor"
		fi
		grep -qx "inventory_events_truncated=$expected_truncated" "$phase_result" || \
			fail "inventory events returned the wrong truncation state on Host $host"
		if [ "$expected_truncated" = true ]; then
			grep -qx 'inventory_events=64' "$phase_result" || \
				fail "inventory Event flood was not bounded on Host $host"
		fi
		if grep -q "$forbidden_event_id" "$phase_result"; then
			fail "inventory events exposed the other Host Runtime ID to Host $host"
		fi
	done
}

run_host_inventory_event_phase() {
	host=$1
	expected_result=$2
	command_suffix=$3
	phase_name=$host-$expected_result-$command_suffix
	phase_ready=$workspace/inventory-events-$phase_name-ready
	phase_result=$workspace/inventory-events-$phase_name-result
	case "$host" in
		a)
			result_a=$phase_result
			result_b=$workspace/inventory-events-$phase_name-unused-b
			only_host=conformance-host-a
			expected_event_id=$event_id_a
			;;
		b)
			result_a=$workspace/inventory-events-$phase_name-unused-a
			result_b=$phase_result
			only_host=conformance-host-b
			expected_event_id=$event_id_b
			;;
		*) fail "single-Host inventory Event phase has an invalid Host" ;;
	esac
	"$tool" serve-dual --listen "$listen" --materials "$materials_a" \
		--ready-file "$phase_ready" --result-a "$result_a" --result-b "$result_b" \
		--only-host "$only_host" --runtime-probe ready \
		--deployment-capabilities=true --inventory-capabilities=true \
		--terminal-capabilities=true \
		--inventory-command runtime.inventory.events --inventory-result "$expected_result" \
		--inventory-event-id-a "$event_id_a" --inventory-event-id-b "$event_id_b" \
		--command-suffix "$command_suffix" --timeout 4m \
		>"$workspace/inventory-events-$phase_name-server.log" 2>&1 &
	server_pid=$!
	wait_for_file "$phase_ready"
	if [ "$expected_result" = unavailable ]; then
		sleep 1
		case "$host" in
			a)
				kill -TERM "$proxy_a_pid" >/dev/null 2>&1 || true
				wait "$proxy_a_pid" >/dev/null 2>&1 || true
				proxy_a_pid=
				;;
			b)
				kill -TERM "$proxy_b_pid" >/dev/null 2>&1 || true
				wait "$proxy_b_pid" >/dev/null 2>&1 || true
				proxy_b_pid=
				;;
		esac
	fi
	wait_for_file "$phase_result" 2100
	wait "$server_pid" || fail "Host $host runtime.inventory.events $expected_result phase failed"
	server_pid=
	grep -qx "managed_host_id=$only_host" "$phase_result" || \
		fail "single-Host inventory Event phase reached the wrong Host"
	grep -qx "command_id=conformance-inventory-events-$only_host-$command_suffix" \
		"$phase_result" || fail "single-Host inventory Event phase returned the wrong command"
	case "$expected_result" in
		succeeded)
			grep -qx 'command_status=inventory_succeeded' "$phase_result" || \
				fail "Host $host inventory Event recovery did not succeed"
			grep -qx "inventory_event_runtime_id=$expected_event_id" "$phase_result" || \
				fail "Host $host inventory Event recovery omitted its Runtime ID"
			grep -qx 'inventory_events_truncated=false' "$phase_result" || \
				fail "Host $host inventory Event recovery unexpectedly truncated"
			;;
		unavailable)
			grep -qx 'command_status=inventory_unavailable' "$phase_result" || \
				fail "Host $host inventory Event disconnect was not classified safely"
			;;
		*) fail "single-Host inventory Event phase has an invalid expected result" ;;
	esac
}

start_host_a_terminal_container() {
	docker exec "$engine_a_id" docker --host tcp://127.0.0.1:2375 run -d \
		--name "$terminal_container" \
		--label net.owndock.deployment_id="$terminal_deployment_id" \
		--label net.owndock.cutover_sequence=1 \
		--label net.owndock.project_id=conformance-project \
		--label net.owndock.application_id=conformance-application \
		--label net.owndock.environment_id=conformance-environment \
		--env TERMINAL_PRIVATE=terminal-private-sentinel-host-a \
		'nginx@sha256:1eff5a5f3fcf8431a0abb7eddf5471fec24e5e1905a2581aeacdb07a4479b92b' \
		>/dev/null
}

wait_for_terminal_records_empty() {
	attempt=0
	while [ "$attempt" -lt 100 ]; do
		if grep -qx '{"version":1,"entries":\[\]}' \
			"$materials_a/state/terminal-executions.json"; then
			return
		fi
		attempt=$((attempt + 1))
		sleep 0.1
	done
	fail "Host A terminal recovery records did not become empty"
}

run_host_container_terminal_fault_phase() {
	fault=$1
	terminal_output_backpressure=false
	[ "$fault" = output-backpressure ] && terminal_output_backpressure=true
	phase_ready=$workspace/container-terminal-$fault-ready
	phase_result=$workspace/container-terminal-$fault-result-a
	unused_result=$workspace/container-terminal-$fault-unused-b
	"$tool" serve-dual --listen "$listen" --materials "$materials_a" \
		--ready-file "$phase_ready" --result-a "$phase_result" \
		--result-b "$unused_result" --only-host conformance-host-a \
		--runtime-probe ready --deployment-capabilities=true \
		--inventory-capabilities=true --terminal-capabilities=true \
		--terminal-container "$terminal_container" \
		--terminal-deployment-id "$terminal_deployment_id" \
		--terminal-cutover-sequence 1 \
		--terminal-output-backpressure="$terminal_output_backpressure" \
		--timeout 20s \
		>"$workspace/container-terminal-$fault-server.log" 2>&1 &
	server_pid=$!
	wait_for_file "$phase_ready"
	attempt=0
	terminal_processes=
	while [ "$attempt" -lt 100 ]; do
		terminal_processes=$(docker exec "$engine_a_id" \
			docker --host tcp://127.0.0.1:2375 top "$terminal_container" -eo pid,args)
		case "$terminal_processes" in
			*'/bin/sh'*) break ;;
		esac
		attempt=$((attempt + 1))
		sleep 0.1
	done
	case "$terminal_processes" in
		*'/bin/sh'*) ;;
		*)
		docker exec "$engine_a_id" docker --host tcp://127.0.0.1:2375 \
			top "$terminal_container" -eo pid,args >&2 || true
		fail "Host A container terminal shell did not open"
			;;
	esac
	case "$fault" in
		exit)
			docker exec "$engine_a_id" docker --host tcp://127.0.0.1:2375 \
				stop --time 5 "$terminal_container" >/dev/null
			;;
		runtime-disconnect)
			kill -TERM "$proxy_a_pid" >/dev/null 2>&1 || true
			wait "$proxy_a_pid" >/dev/null 2>&1 || true
			proxy_a_pid=
			;;
		target-replacement)
			original_container_id=$(docker exec "$engine_a_id" \
				docker --host tcp://127.0.0.1:2375 inspect \
				--format '{{.Id}}' "$terminal_container")
			docker exec "$engine_a_id" docker --host tcp://127.0.0.1:2375 \
				rm -f "$terminal_container" >/dev/null
			start_host_a_terminal_container
			replacement_container_id=$(docker exec "$engine_a_id" \
				docker --host tcp://127.0.0.1:2375 inspect \
				--format '{{.Id}}' "$terminal_container")
			[ "$replacement_container_id" != "$original_container_id" ] || \
				fail "Host A terminal target replacement preserved the old container ID"
			;;
		agent-restart)
			kill -KILL "$agent_a_pid" >/dev/null 2>&1 || \
				fail "could not interrupt Host A Agent during its terminal session"
			wait "$agent_a_pid" >/dev/null 2>&1 || true
			agent_a_pid=
			;;
		output-backpressure)
			attempt=0
			while [ "$attempt" -lt 100 ]; do
				terminal_processes=$(docker exec "$engine_a_id" \
					docker --host tcp://127.0.0.1:2375 top \
					"$terminal_container" -eo pid,args)
				case "$terminal_processes" in
					*'/bin/sh'*) ;;
					*) break ;;
				esac
				attempt=$((attempt + 1))
				sleep 0.1
			done
			case "$terminal_processes" in
				*'/bin/sh'*) fail "Host A terminal output backpressure left its shell running" ;;
			esac
			;;
		*) fail "container terminal fault is invalid" ;;
	esac
	wait_for_file "$phase_result" 200
	wait "$server_pid" || fail "Host A container terminal $fault phase failed"
	server_pid=
	[ ! -e "$unused_result" ] || fail "container terminal crossed Host identity"
	grep -qx 'managed_host_id=conformance-host-a' "$phase_result" || \
		fail "container terminal reached the wrong Host"
	grep -qx 'terminal_session_id=conformance-container-terminal' "$phase_result" || \
		fail "container terminal returned the wrong session"
	grep -qx 'terminal_status=frames_sent' "$phase_result" || \
		fail "container terminal frames were not sent"
}

run_host_a_probe_after_terminal() {
	fault=$1
	phase_ready=$workspace/container-terminal-$fault-recovery-ready
	phase_result=$workspace/container-terminal-$fault-recovery-result-a
	unused_result=$workspace/container-terminal-$fault-recovery-unused-b
	"$tool" serve-dual --listen "$listen" --materials "$materials_a" \
		--ready-file "$phase_ready" --result-a "$phase_result" \
		--result-b "$unused_result" --only-host conformance-host-a \
		--runtime-probe ready --command-suffix "terminal-$fault-recovery" \
		--deployment-capabilities=true --inventory-capabilities=true \
		--terminal-capabilities=true --timeout 45s \
		>"$workspace/container-terminal-$fault-recovery-server.log" 2>&1 &
	server_pid=$!
	wait_for_file "$phase_ready"
	wait_for_file "$phase_result" 450
	wait "$server_pid" || fail "Host A did not reconnect after terminal $fault fault"
	server_pid=
	[ ! -e "$unused_result" ] || fail "terminal recovery probe crossed Host identity"
	grep -qx 'managed_host_id=conformance-host-a' "$phase_result" || \
		fail "terminal recovery probe reached the wrong Host"
	grep -qx 'command_status=runtime_ready' "$phase_result" || \
		fail "Host A runtime did not recover after terminal $fault fault"
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
	--deployment-capabilities="$deployment_capabilities" \
	--inventory-capabilities="$inventory_capabilities" \
	--terminal-capabilities="$terminal_capabilities" \
	>"$workspace/server-one.log" 2>&1 &
server_pid=$!
wait_for_file "$ready_one"
endpoint=$(tr -d '\r\n' < "$ready_one")
listen=${endpoint#https://}
listen=${listen%/api/v1/agent/connect}
"$tool" config --output "$materials_a" --endpoint "$endpoint" \
	--host-id conformance-host-a --docker-socket "$docker_socket_a" \
	--deployment-capabilities="$deployment_capabilities" \
	--inventory-capabilities="$inventory_capabilities" \
	--terminal-capabilities="$terminal_capabilities"
"$tool" config --output "$materials_b" --endpoint "$endpoint" \
	--host-id conformance-host-b --docker-socket "$docker_socket_b" \
	--deployment-capabilities="$deployment_capabilities" \
	--inventory-capabilities="$inventory_capabilities" \
	--terminal-capabilities="$terminal_capabilities"

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
	--deployment-capabilities="$deployment_capabilities" \
	--inventory-capabilities="$inventory_capabilities" \
	--terminal-capabilities="$terminal_capabilities" \
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
	--deployment-capabilities="$deployment_capabilities" \
	--inventory-capabilities="$inventory_capabilities" \
	--terminal-capabilities="$terminal_capabilities" \
	--timeout 45s \
    >"$workspace/server-three.log" 2>&1 &
server_pid=$!
wait_for_file "$ready_three"
wait_for_file "$result_a_three" 450
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
		--deployment-capabilities=true \
		--inventory-capabilities=true \
		--terminal-capabilities=true \
		--timeout 45s \
		>"$workspace/server-four.log" 2>&1 &
	server_pid=$!
	wait_for_file "$ready_four"
	wait_for_file "$result_a_four" 450
	wait "$server_pid" || fail "Host A runtime did not recover after Engine restart"
	server_pid=
	grep -qx 'managed_host_id=conformance-host-a' "$result_a_four" || \
		fail "Host A runtime recovery crossed routes"
	grep -qx 'command_id=conformance-probe-conformance-host-a-host-a-recovery' "$result_a_four" || \
		fail "Host A runtime recovery received the wrong command"
	grep -qx 'command_status=runtime_ready' "$result_a_four" || \
		fail "Host A runtime did not become ready after Engine restart"

	deployment_container=owndock-dual-agent-runtime
	run_dual_deployment_phase deployment.prepare
	run_dual_deployment_phase deployment.stage
	run_dual_deployment_phase deployment.activate
	state_a=$(docker exec "$engine_a_id" docker --host tcp://127.0.0.1:2375 \
		inspect --format '{{.State.Running}} {{index .Config.Labels "net.owndock.deployment_id"}}' \
		"$deployment_container")
	state_b=$(docker exec "$engine_b_id" docker --host tcp://127.0.0.1:2375 \
		inspect --format '{{.State.Running}} {{index .Config.Labels "net.owndock.deployment_id"}}' \
		"$deployment_container")
	[ "$state_a" = 'true conformance-deployment-conformance-host-a' ] || \
		fail "Host A stable deployment identity is invalid: $state_a"
	[ "$state_b" = 'true conformance-deployment-conformance-host-b' ] || \
		fail "Host B stable deployment identity is invalid: $state_b"
	run_dual_inventory_phase runtime.inventory.prepare
	run_dual_inventory_phase runtime.inventory.chunk
	run_dual_inventory_phase runtime.inventory.release
	event_id_a=$(docker exec "$engine_a_id" docker --host tcp://127.0.0.1:2375 \
		create --name owndock-event-a \
		'nginx@sha256:1eff5a5f3fcf8431a0abb7eddf5471fec24e5e1905a2581aeacdb07a4479b92b')
	event_id_b=$(docker exec "$engine_b_id" docker --host tcp://127.0.0.1:2375 \
		create --name owndock-event-b \
		'nginx@sha256:1eff5a5f3fcf8431a0abb7eddf5471fec24e5e1905a2581aeacdb07a4479b92b')
	case "$event_id_a:$event_id_b" in
		*[!0-9a-f:]* | "$event_id_a:$event_id_a")
			fail "isolated Docker Event Runtime IDs are invalid"
			;;
	esac
	[ "${#event_id_a}" -eq 64 ] && [ "${#event_id_b}" -eq 64 ] || \
		fail "isolated Docker Event Runtime IDs have invalid lengths"
	run_dual_inventory_event_phase false dual-runtime
	run_dual_inventory_event_phase false inclusive-replay \
		"$event_cursor_a" "$event_cursor_b"
	run_host_inventory_event_phase a unavailable event-outage
	run_host_inventory_event_phase b succeeded host-a-outage
	rm -f "$docker_socket_a"
	proxy_a_ready=$workspace/proxy-a-event-recovery-ready
	"$tool" docker-proxy --listen "$docker_socket_a" --upstream "$engine_a_address" \
		--ready-file "$proxy_a_ready" >"$workspace/proxy-a-event-recovery.log" 2>&1 &
	proxy_a_pid=$!
	wait_for_file "$proxy_a_ready"
	event_id_a=$(docker exec "$engine_a_id" docker --host tcp://127.0.0.1:2375 \
		create --name owndock-event-a-recovered \
		'nginx@sha256:1eff5a5f3fcf8431a0abb7eddf5471fec24e5e1905a2581aeacdb07a4479b92b')
	[ "${#event_id_a}" -eq 64 ] || fail "recovered Host A Docker Event Runtime ID is invalid"
	run_host_inventory_event_phase a succeeded event-recovery
	for engine_host in a b; do
		case "$engine_host" in
			a)
				event_engine=$engine_a_id
				event_secret=event-private-sentinel-host-a
				;;
			b)
				event_engine=$engine_b_id
				event_secret=event-private-sentinel-host-b
				;;
		esac
		docker exec "$event_engine" sh -ec '
			i=0
			while [ "$i" -lt 70 ]; do
				docker --host tcp://127.0.0.1:2375 create \
					--name "owndock-event-flood-$1-$i" \
					--label "private.event=$2" "$3" >/dev/null
				i=$((i + 1))
			done
		' sh "$engine_host" "$event_secret" \
			'nginx@sha256:1eff5a5f3fcf8431a0abb7eddf5471fec24e5e1905a2581aeacdb07a4479b92b'
	done
	run_dual_inventory_event_phase true event-flood
	docker logs "$engine_a_id" >"$workspace/engine-a.log" 2>&1 || \
		fail "could not capture Host A Engine logs for secret scan"
	docker logs "$engine_b_id" >"$workspace/engine-b.log" 2>&1 || \
		fail "could not capture Host B Engine logs for secret scan"
	if find "$workspace" -type f -exec \
		grep -E 'event-private-sentinel-host-(a|b)' {} + >/dev/null; then
		fail "Docker Event Actor attributes leaked into Agent results or process logs"
	fi

	# An abrupt Agent process loss must not erase its independently persisted
	# cutover watermark. Host B remains available, while Host A restarts from the
	# same state directory, activates a newer deployment, and rejects a delayed
	# sequence-one activate after the restart.
	kill -KILL "$agent_a_pid" >/dev/null 2>&1 || fail "could not interrupt Host A Agent"
	wait "$agent_a_pid" >/dev/null 2>&1 || true
	agent_a_pid=
	"$agent" -conf "$materials_a/agent.yaml" >>"$workspace/agent-a.log" 2>&1 &
	agent_a_pid=$!
	run_host_deployment_phase a deployment.prepare 2 succeeded restart-v2
	run_host_deployment_phase a deployment.stage 2 succeeded restart-v2
	run_host_deployment_phase a deployment.activate 2 succeeded restart-v2
	run_host_deployment_phase a deployment.activate 1 stale_execution delayed-v1
	state_a=$(docker exec "$engine_a_id" docker --host tcp://127.0.0.1:2375 \
		inspect --format '{{.State.Running}} {{index .Config.Labels "net.owndock.deployment_id"}} {{index .Config.Labels "net.owndock.cutover_sequence"}}' \
		"$deployment_container")
	state_b=$(docker exec "$engine_b_id" docker --host tcp://127.0.0.1:2375 \
		inspect --format '{{.State.Running}} {{index .Config.Labels "net.owndock.deployment_id"}} {{index .Config.Labels "net.owndock.cutover_sequence"}}' \
		"$deployment_container")
	[ "$state_a" = 'true conformance-deployment-conformance-host-a-v2 2' ] || \
		fail "Host A did not preserve its cutover watermark across Agent restart: $state_a"
	[ "$state_b" = 'true conformance-deployment-conformance-host-b 1' ] || \
		fail "Host A Agent restart changed Host B deployment: $state_b"

	terminal_deployment_id=conformance-terminal-deployment-a
	terminal_container=$("$tool" container-name \
		--project conformance-project \
		--application conformance-application \
		--environment conformance-environment \
		--runtime-target conformance-target-conformance-host-a)
	case "$terminal_container" in
		owndock-[0-9a-f][0-9a-f]*) ;;
		*) fail "canonical Host A terminal container name is invalid" ;;
	esac
	start_host_a_terminal_container
	run_host_container_terminal_fault_phase exit
	attempt=0
	while [ "$attempt" -lt 100 ]; do
		terminal_running=$(docker exec "$engine_a_id" docker --host tcp://127.0.0.1:2375 \
			inspect --format '{{.State.Running}}' "$terminal_container")
		[ "$terminal_running" = false ] && break
		attempt=$((attempt + 1))
		sleep 0.1
	done
	[ "$terminal_running" = false ] || fail "Host A terminal target did not exit"
	run_host_a_probe_after_terminal exit
	docker exec "$engine_a_id" docker --host tcp://127.0.0.1:2375 \
		start "$terminal_container" >/dev/null
	run_host_container_terminal_fault_phase runtime-disconnect
	terminal_running=$(docker exec "$engine_a_id" docker --host tcp://127.0.0.1:2375 \
		inspect --format '{{.State.Running}}' "$terminal_container")
	[ "$terminal_running" = true ] || \
		fail "Host A terminal runtime disconnect stopped the target container"
	rm -f "$docker_socket_a"
	proxy_a_ready=$workspace/proxy-a-terminal-recovery-ready
	"$tool" docker-proxy --listen "$docker_socket_a" --upstream "$engine_a_address" \
		--ready-file "$proxy_a_ready" >"$workspace/proxy-a-terminal-recovery.log" 2>&1 &
	proxy_a_pid=$!
	wait_for_file "$proxy_a_ready"
	run_host_a_probe_after_terminal runtime-disconnect
	run_host_container_terminal_fault_phase target-replacement
	terminal_replacement_running=$(docker exec "$engine_a_id" \
		docker --host tcp://127.0.0.1:2375 inspect \
		--format '{{.State.Running}}' "$replacement_container_id")
	[ "$terminal_replacement_running" = true ] || \
		fail "Host A replacement terminal target did not remain running"
	run_host_a_probe_after_terminal target-replacement
	run_host_container_terminal_fault_phase agent-restart
	"$agent" -conf "$materials_a/agent.yaml" >>"$workspace/agent-a.log" 2>&1 &
	agent_a_pid=$!
	attempt=0
	while [ "$attempt" -lt 100 ]; do
		if ! kill -0 "$agent_a_pid" >/dev/null 2>&1; then
			tail -20 "$workspace/agent-a.log" >&2 || true
			fail "Host A Agent exited while recovering its terminal shell"
		fi
		terminal_processes=$(docker exec "$engine_a_id" \
			docker --host tcp://127.0.0.1:2375 top "$terminal_container" -eo pid,args)
		case "$terminal_processes" in
			*'/bin/sh'*) ;;
			*) break ;;
		esac
		attempt=$((attempt + 1))
		sleep 0.1
	done
	case "$terminal_processes" in
		*'/bin/sh'*) fail "Host A Agent restart left its terminal shell running" ;;
	esac
	wait_for_terminal_records_empty
	run_host_a_probe_after_terminal agent-restart
	run_host_container_terminal_fault_phase output-backpressure
	wait_for_terminal_records_empty
	run_host_a_probe_after_terminal output-backpressure
	state_b_after_terminal=$(docker exec "$engine_b_id" docker --host tcp://127.0.0.1:2375 \
		inspect --format '{{.State.Running}} {{index .Config.Labels "net.owndock.deployment_id"}} {{index .Config.Labels "net.owndock.cutover_sequence"}}' \
		"$deployment_container")
	[ "$state_b_after_terminal" = 'true conformance-deployment-conformance-host-b 1' ] || \
		fail "Host A terminal target exit changed Host B deployment"
	docker logs "$engine_a_id" >"$workspace/engine-a-after-terminal.log" 2>&1 || \
		fail "could not capture Host A Engine logs after terminal exit"
	if find "$workspace" -type f -exec \
		grep -F 'terminal-private-sentinel-host-a' {} + >/dev/null; then
		fail "container terminal exposed private environment data in process logs"
	fi
fi

kill -TERM "$agent_a_pid"
wait "$agent_a_pid" || fail "Host A Agent did not stop cleanly"
agent_a_pid=
kill -TERM "$agent_b_pid"
wait "$agent_b_pid" || fail "Host B Agent did not stop cleanly"
agent_b_pid=

if [ "$runtime_mode" = 1 ]; then
	printf '%s\n' "OwnDock dual Agent processes, isolated Engines, deployment, container terminal exit/disconnect/replacement/Agent-restart/backpressure recovery, secret-safe bounded inventory Event flood, outage and restart fencing passed"
else
	printf '%s\n' "OwnDock shared-control dual Agent routing and single-Host rejection recovery passed"
fi
