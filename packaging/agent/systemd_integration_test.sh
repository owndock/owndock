#!/bin/sh
set -eu

fail() {
    printf '%s\n' "Agent systemd integration failed: $1" >&2
    exit 1
}

[ "$#" -eq 1 ] || fail "usage: systemd_integration_test.sh FAKE_AGENT_BINARY"
fixture=$1
[ "$(uname -s)" = Linux ] || fail "this test requires Linux"
[ "$(id -u)" -eq 0 ] || fail "this test requires root"
[ "$(awk -F= '$1 == "ID" { gsub(/\"/, "", $2); print $2 }' /etc/os-release)" = ubuntu ] || \
    fail "this test requires Ubuntu"
[ "$(awk -F= '$1 == "VERSION_ID" { gsub(/\"/, "", $2); print $2 }' /etc/os-release)" = 24.04 ] || \
    fail "this test requires Ubuntu 24.04"
[ -s /sys/fs/cgroup/cgroup.controllers ] || fail "this test requires cgroup v2"
[ -f "$fixture" ] && [ ! -L "$fixture" ] && [ -x "$fixture" ] || \
    fail "fixture must be an executable regular file"
command -v systemctl >/dev/null 2>&1 || fail "systemctl is unavailable"
systemctl show-environment >/dev/null 2>&1 || fail "systemd is not running"
getent group docker >/dev/null 2>&1 || fail "docker group is unavailable"
[ -x /usr/bin/docker ] || fail "Docker must be installed at /usr/bin/docker"
[ "$(docker version --format '{{.Server.Version}}')" = 29.6.1 ] || \
    fail "this test requires Docker Engine 29.6.1"
[ "$(docker info --format '{{.CgroupVersion}}')" = 2 ] || \
    fail "this test requires Docker cgroup v2"
docker compose version >/dev/null 2>&1 || fail "Docker Compose v2 is unavailable"

ingress_project=owndock-ingress
port_blocker=owndock-ingress-port-conflict
fixture_image=nginx@sha256:1eff5a5f3fcf8431a0abb7eddf5471fec24e5e1905a2581aeacdb07a4479b92b

for protected_path in \
    /opt/owndock-agent \
    /etc/owndock \
    /etc/systemd/system/owndock-agent.service \
    /etc/systemd/system/owndock-ingress.service \
    /var/lib/owndock-agent \
    /var/lib/owndock-ingress \
    /usr/local/sbin/owndock-agentctl; do
    [ ! -e "$protected_path" ] && [ ! -L "$protected_path" ] || \
        fail "refusing to overwrite existing path: $protected_path"
done
id owndock-agent >/dev/null 2>&1 && fail "refusing to reuse existing owndock-agent account"
id owndock-ingress >/dev/null 2>&1 && fail "refusing to reuse existing owndock-ingress account"

workspace=$(mktemp -d /tmp/owndock-agent-systemd.XXXXXX)
cleanup() {
    systemctl disable --now owndock-agent.service >/dev/null 2>&1 || true
    systemctl disable --now owndock-ingress.service >/dev/null 2>&1 || true
    docker rm -f -v "$port_blocker" >/dev/null 2>&1 || true
    if [ -f /etc/owndock/ingress.env ] && \
       [ -f /opt/owndock-agent/current/owndock-ingress.compose.yaml ]; then
        docker compose --project-name "$ingress_project" \
            --env-file /etc/owndock/ingress.env \
            -f /opt/owndock-agent/current/owndock-ingress.compose.yaml \
            down --remove-orphans >/dev/null 2>&1 || true
    fi
    rm -f /etc/systemd/system/owndock-agent.service
    rm -f /etc/systemd/system/owndock-ingress.service
    rm -f /usr/local/sbin/owndock-agentctl
    rm -rf /opt/owndock-agent
    rm -rf /etc/owndock
    rm -rf /var/lib/owndock-agent
    rm -rf /var/lib/owndock-ingress
    rm -f /etc/owndock-agent-systemd-escape
    systemctl daemon-reload >/dev/null 2>&1 || true
    systemctl reset-failed owndock-agent.service >/dev/null 2>&1 || true
    userdel owndock-agent >/dev/null 2>&1 || true
    userdel owndock-ingress >/dev/null 2>&1 || true
    rm -rf "$workspace"
}
trap cleanup EXIT HUP INT TERM

repository=$(CDPATH='' cd "$(dirname "$0")/../.." && pwd -P)

create_package() {
    version=$1
    package=$workspace/package-$version
    install -d -m 0755 "$package"
    install -m 0755 "$fixture" "$package/owndock-agent"
    install -m 0755 "$repository/packaging/agent/owndock-agentctl" "$package/owndock-agentctl"
    install -m 0644 "$repository/packaging/agent/owndock-agent.service" "$package/owndock-agent.service"
    install -m 0644 "$repository/packaging/agent/owndock-ingress.service" "$package/owndock-ingress.service"
    install -m 0640 "$repository/packaging/agent/owndock-ingress.compose.yaml" "$package/owndock-ingress.compose.yaml"
    install -m 0640 "$repository/packaging/agent/owndock-ingress-bootstrap.json" "$package/owndock-ingress-bootstrap.json"
    install -m 0644 "$repository/packaging/agent/owndock-ingress-image.json" "$package/owndock-ingress-image.json"
    install -m 0640 "$repository/configs/agent.yaml" "$package/agent.yaml.example"
    printf '%s\n' "$version" > "$package/VERSION"
    sha256sum "$package/owndock-agent" | awk '{ print $1 }' > "$package/owndock-agent.sha256"
    printf '%s\n' "$package"
}

wait_for_version() {
    expected=$1
    attempt=0
    while [ "$attempt" -lt 20 ]; do
        if [ -f /var/lib/owndock-agent/systemd-running-version ] && \
           [ "$(tr -d '\r\n' < /var/lib/owndock-agent/systemd-running-version)" = "$expected" ]; then
            return
        fi
        attempt=$((attempt + 1))
        sleep 1
    done
    fail "service did not report version $expected"
}

assert_ingress_active() {
    systemctl is-active --quiet owndock-ingress.service || \
        fail "managed Ingress service is not active"
    [ -S /run/owndock-ingress/admin.sock ] || \
        fail "managed Ingress admin socket is unavailable"
    [ "$(docker inspect -f '{{.State.Running}}' owndock-ingress 2>/dev/null)" = true ] || \
        fail "managed Ingress container is not running"
}

assert_ingress_state() {
    [ "$(tr -d '\r\n' < /var/lib/owndock-ingress/data/systemd-preserved-state)" = \
        preserved-ingress-state ] || fail "managed Ingress state changed across release operation"
}

package_one=$(create_package 1.0.0)
"$package_one/owndock-agentctl" install
install -o root -g owndock-agent -m 0640 /dev/null /etc/owndock/agent.yaml
install -o root -g owndock-agent -m 0640 /dev/null /etc/owndock/agent-ca.pem
install -o owndock-agent -g owndock-agent -m 0600 /dev/null \
    /var/lib/owndock-agent/identity/agent-identity.pem
"$package_one/owndock-agentctl" install --start
systemctl is-active --quiet owndock-agent.service || fail "initial service is not active"
wait_for_version 1.0.0
[ "$(stat -c %G /opt/owndock-agent/current/owndock-ingress.compose.yaml)" = owndock-agent ] || \
    fail "Ingress Compose file is not readable by the service group"
[ "$(stat -c %a /opt/owndock-agent/current/owndock-ingress.compose.yaml)" = 640 ] || \
    fail "Ingress Compose file mode is not restricted"

for public_port in 80 443; do
    docker run --detach --name "$port_blocker" \
        --publish "$public_port:80/tcp" "$fixture_image" >/dev/null
    if systemctl start owndock-ingress.service; then
        fail "managed Ingress unexpectedly started while TCP port $public_port was occupied"
    fi
    systemctl is-active --quiet owndock-ingress.service && \
        fail "managed Ingress remained active after the TCP port $public_port conflict"
    docker rm -f -v "$port_blocker" >/dev/null
    systemctl reset-failed owndock-ingress.service
done
systemctl enable --now owndock-ingress.service
assert_ingress_active
printf '%s\n' preserved-ingress-state > /var/lib/owndock-ingress/data/systemd-preserved-state
chown owndock-ingress:owndock-agent /var/lib/owndock-ingress/data/systemd-preserved-state
chmod 0600 /var/lib/owndock-ingress/data/systemd-preserved-state

printf '%s\n' preserved-state > /var/lib/owndock-agent/systemd-preserved-state
printf '%s\n' '{"version":1,"entries":[]}' > \
    /var/lib/owndock-agent/terminal-executions.json
chown owndock-agent:owndock-agent /var/lib/owndock-agent/terminal-executions.json
chmod 0600 /var/lib/owndock-agent/terminal-executions.json

package_two=$(create_package 1.1.0)
"$package_two/owndock-agentctl" install
systemctl is-active --quiet owndock-agent.service || fail "upgraded service is not active"
wait_for_version 1.1.0
assert_ingress_active
assert_ingress_state
systemctl reset-failed owndock-ingress.service

package_bad=$(create_package 9.9.9)
if "$package_bad/owndock-agentctl" install; then
    fail "startup-failing release unexpectedly installed"
fi
[ "$(readlink /opt/owndock-agent/current)" = releases/1.1.0 ] || \
    fail "failed release did not restore the previous current symlink"
systemctl is-active --quiet owndock-agent.service || fail "previous service was not restored"
wait_for_version 1.1.0
assert_ingress_active
assert_ingress_state
[ "$(tr -d '\r\n' < /var/lib/owndock-agent/systemd-preserved-state)" = preserved-state ] || \
    fail "runtime state changed during upgrade recovery"
[ "$(tr -d '\r\n' < /var/lib/owndock-agent/terminal-executions.json)" = \
    '{"version":1,"entries":[]}' ] || \
    fail "terminal recovery state changed during upgrade recovery"

chown root:root \
    /opt/owndock-agent/releases/1.0.0/owndock-ingress.compose.yaml \
    /opt/owndock-agent/releases/1.0.0/owndock-ingress-bootstrap.json
chmod 0640 \
    /opt/owndock-agent/releases/1.0.0/owndock-ingress.compose.yaml \
    /opt/owndock-agent/releases/1.0.0/owndock-ingress-bootstrap.json
systemctl reset-failed owndock-ingress.service
/usr/local/sbin/owndock-agentctl rollback --version 1.0.0
systemctl is-active --quiet owndock-agent.service || fail "rolled back service is not active"
wait_for_version 1.0.0
assert_ingress_active
assert_ingress_state
[ "$(stat -c %G /opt/owndock-agent/current/owndock-ingress.compose.yaml)" = owndock-agent ] || \
    fail "rollback did not repair the Ingress service group"
[ "$(tr -d '\r\n' < /var/lib/owndock-agent/systemd-preserved-state)" = preserved-state ] || \
    fail "runtime state changed during rollback"
[ "$(tr -d '\r\n' < /var/lib/owndock-agent/terminal-executions.json)" = \
    '{"version":1,"entries":[]}' ] || \
    fail "terminal recovery state changed during rollback"

[ "$(systemctl show owndock-agent.service -p User --value)" = owndock-agent ] || \
    fail "systemd user hardening is missing"
[ "$(systemctl show owndock-agent.service -p NoNewPrivileges --value)" = yes ] || \
    fail "NoNewPrivileges is not active"
[ "$(systemctl show owndock-agent.service -p ProtectSystem --value)" = strict ] || \
    fail "ProtectSystem is not strict"
[ "$(systemctl show owndock-ingress.service -p User --value)" = owndock-ingress ] || \
    fail "managed Ingress systemd user hardening is missing"
[ "$(systemctl show owndock-ingress.service -p NoNewPrivileges --value)" = yes ] || \
    fail "managed Ingress NoNewPrivileges is not active"
[ "$(systemctl show owndock-ingress.service -p ProtectSystem --value)" = strict ] || \
    fail "managed Ingress ProtectSystem is not strict"

printf '%s\n' "OwnDock Agent systemd lifecycle integration passed"
