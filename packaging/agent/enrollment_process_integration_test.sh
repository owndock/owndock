#!/bin/sh
set -eu

fail() {
    printf '%s\n' "Agent enrollment process integration failed: $1" >&2
    exit 1
}

[ "$#" -eq 2 ] || fail "usage: enrollment_process_integration_test.sh AGENT FIXTURE_SERVER"
agent=$1
fixture_server=$2
[ "$(uname -s)" = Linux ] || fail "this test requires Linux"
[ "$(id -u)" -eq 0 ] || fail "this test requires root"
for executable in "$agent" "$fixture_server"; do
    [ -f "$executable" ] && [ ! -L "$executable" ] && [ -x "$executable" ] || \
        fail "input must be an executable regular file: $executable"
done
for protected_path in /etc/owndock /var/lib/owndock-agent; do
    [ ! -e "$protected_path" ] && [ ! -L "$protected_path" ] || \
        fail "refusing to overwrite existing path: $protected_path"
done

workspace=$(mktemp -d /tmp/owndock-agent-enrollment.XXXXXX)
server_pid=
cleanup() {
    if [ -n "$server_pid" ]; then
        kill "$server_pid" >/dev/null 2>&1 || true
        wait "$server_pid" >/dev/null 2>&1 || true
    fi
    rm -rf /etc/owndock
    rm -rf /var/lib/owndock-agent
    rm -rf "$workspace"
}
trap cleanup EXIT HUP INT TERM

materials=$workspace/materials
ready=$workspace/ready
first_request=$workspace/first-request.json
second_request=$workspace/second-request.json
token_file=$workspace/enrollment-token
token=conformance-one-time-token-0123456789abcdef
"$fixture_server" materials --output "$materials"
printf '%s\n' "$token" > "$token_file"
chmod 0600 "$token_file"
install -d -m 0750 /etc/owndock
install -d -m 0700 /var/lib/owndock-agent
install -d -m 0700 /var/lib/owndock-agent/identity

wait_for_ready() {
    attempt=0
    while [ "$attempt" -lt 100 ]; do
        if [ -s "$ready" ]; then
            return
        fi
        if ! kill -0 "$server_pid" >/dev/null 2>&1; then
            wait "$server_pid" || true
            fail "fixture server exited before becoming ready"
        fi
        attempt=$((attempt + 1))
        sleep 0.1
    done
    fail "fixture server did not become ready"
}

"$fixture_server" serve \
    --materials "$materials" --ready-file "$ready" --request-file "$first_request" \
    --mode drop --token "$token" >"$workspace/drop-server.log" 2>&1 &
server_pid=$!
wait_for_ready
endpoint=$(tr -d '\r\n' < "$ready")
address=${endpoint#https://}
address=${address%%/*}
case "$address" in
    127.0.0.1:*) ;;
    *) fail "fixture returned a non-loopback endpoint" ;;
esac

enroll() {
    "$agent" enroll \
        --enrollment-endpoint "$endpoint" \
        --control-endpoint "https://127.0.0.1:8443/api/v1/agent/connect" \
        --server-ca-file "$materials/ca.pem" \
        --token-file "$token_file" \
        --instance-id conformance-instance \
        --timeout 5s
}

if enroll >"$workspace/first-client.log" 2>&1; then
    fail "interrupted exchange unexpectedly succeeded"
fi
wait "$server_pid"
server_pid=
pending=/var/lib/owndock-agent/enrollment-pending-v1.json
[ -f "$pending" ] && [ ! -L "$pending" ] || fail "request phase was not persisted"
[ "$(stat -c %a "$pending")" = 600 ] || fail "pending request is not private"
if grep -F "$token" "$pending" "$workspace/first-client.log" "$workspace/drop-server.log" >/dev/null; then
    fail "enrollment token leaked into persistent state or logs"
fi

ln -s /dev/null /etc/owndock/agent-ca.pem
rm -f "$ready"
"$fixture_server" serve \
    --listen "$address" --materials "$materials" --ready-file "$ready" \
    --request-file "$second_request" --expected-request-file "$first_request" \
    --mode respond --token "$token" >"$workspace/respond-server.log" 2>&1 &
server_pid=$!
wait_for_ready
if enroll >"$workspace/second-client.log" 2>&1; then
    fail "unsafe local CA target unexpectedly accepted the response"
fi
wait "$server_pid"
server_pid=
cmp -s "$first_request" "$second_request" || fail "retry changed the enrollment request"
[ -f "$pending" ] && [ ! -L "$pending" ] || fail "response phase was not persisted"
[ ! -e /etc/owndock/agent.yaml ] || fail "config committed before enrollment recovery"

rm -f /etc/owndock/agent-ca.pem
rm -f "$token_file"
"$agent" enroll --recover >"$workspace/recover-client.log" 2>&1
[ ! -e "$pending" ] && [ ! -L "$pending" ] || fail "pending response remains after recovery"
for installed in \
    /etc/owndock/agent.yaml \
    /etc/owndock/agent-ca.pem \
    /var/lib/owndock-agent/identity/agent-identity.pem \
    /var/lib/owndock-agent/instance-id; do
    [ -f "$installed" ] && [ ! -L "$installed" ] || fail "missing installed file: $installed"
done
[ "$(stat -c %a /etc/owndock/agent.yaml)" = 640 ] || fail "config mode is not 0640"
[ "$(stat -c %a /etc/owndock/agent-ca.pem)" = 640 ] || fail "CA mode is not 0640"
[ "$(stat -c %a /var/lib/owndock-agent/identity/agent-identity.pem)" = 600 ] || \
    fail "identity mode is not 0600"
[ "$(stat -c %a /var/lib/owndock-agent/instance-id)" = 600 ] || \
    fail "instance ID mode is not 0600"
grep -Fq "organization_id: conformance-organization" /etc/owndock/agent.yaml || \
    fail "installed config has the wrong organization"
grep -Fq "managed_host_id: conformance-host" /etc/owndock/agent.yaml || \
    fail "installed config has the wrong host"
grep -Fq "identity_id: conformance-identity" /etc/owndock/agent.yaml || \
    fail "installed config has the wrong identity"
if grep -R -F "$token" /etc/owndock /var/lib/owndock-agent "$workspace"/*.log >/dev/null; then
    fail "enrollment token leaked after recovery"
fi

printf '%s\n' "OwnDock Agent enrollment network and local recovery integration passed"
