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
[ -f "$fixture" ] && [ ! -L "$fixture" ] && [ -x "$fixture" ] || \
    fail "fixture must be an executable regular file"
command -v systemctl >/dev/null 2>&1 || fail "systemctl is unavailable"
systemctl show-environment >/dev/null 2>&1 || fail "systemd is not running"
getent group docker >/dev/null 2>&1 || fail "docker group is unavailable"

for protected_path in \
    /opt/owndock-agent \
    /etc/owndock \
    /etc/systemd/system/owndock-agent.service \
    /var/lib/owndock-agent \
    /usr/local/sbin/owndock-agentctl; do
    [ ! -e "$protected_path" ] && [ ! -L "$protected_path" ] || \
        fail "refusing to overwrite existing path: $protected_path"
done
id owndock-agent >/dev/null 2>&1 && fail "refusing to reuse existing owndock-agent account"

workspace=$(mktemp -d /tmp/owndock-agent-systemd.XXXXXX)
cleanup() {
    systemctl disable --now owndock-agent.service >/dev/null 2>&1 || true
    rm -f /etc/systemd/system/owndock-agent.service
    rm -f /usr/local/sbin/owndock-agentctl
    rm -rf /opt/owndock-agent
    rm -rf /etc/owndock
    rm -rf /var/lib/owndock-agent
    rm -f /etc/owndock-agent-systemd-escape
    systemctl daemon-reload >/dev/null 2>&1 || true
    systemctl reset-failed owndock-agent.service >/dev/null 2>&1 || true
    userdel owndock-agent >/dev/null 2>&1 || true
    rm -rf "$workspace"
}
trap cleanup EXIT HUP INT TERM

repository=$(CDPATH= cd "$(dirname "$0")/../.." && pwd -P)

create_package() {
    version=$1
    package=$workspace/package-$version
    install -d -m 0755 "$package"
    install -m 0755 "$fixture" "$package/owndock-agent"
    install -m 0755 "$repository/packaging/agent/owndock-agentctl" "$package/owndock-agentctl"
    install -m 0644 "$repository/packaging/agent/owndock-agent.service" "$package/owndock-agent.service"
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

package_one=$(create_package 1.0.0)
"$package_one/owndock-agentctl" install
install -o root -g owndock-agent -m 0640 /dev/null /etc/owndock/agent.yaml
install -o root -g owndock-agent -m 0640 /dev/null /etc/owndock/agent-ca.pem
install -o owndock-agent -g owndock-agent -m 0600 /dev/null \
    /var/lib/owndock-agent/identity/agent-identity.pem
"$package_one/owndock-agentctl" install --start
systemctl is-active --quiet owndock-agent.service || fail "initial service is not active"
wait_for_version 1.0.0
printf '%s\n' preserved-state > /var/lib/owndock-agent/systemd-preserved-state

package_two=$(create_package 1.1.0)
"$package_two/owndock-agentctl" install
systemctl is-active --quiet owndock-agent.service || fail "upgraded service is not active"
wait_for_version 1.1.0

package_bad=$(create_package 9.9.9)
if "$package_bad/owndock-agentctl" install; then
    fail "startup-failing release unexpectedly installed"
fi
[ "$(readlink /opt/owndock-agent/current)" = releases/1.1.0 ] || \
    fail "failed release did not restore the previous current symlink"
systemctl is-active --quiet owndock-agent.service || fail "previous service was not restored"
wait_for_version 1.1.0
[ "$(tr -d '\r\n' < /var/lib/owndock-agent/systemd-preserved-state)" = preserved-state ] || \
    fail "runtime state changed during upgrade recovery"

/usr/local/sbin/owndock-agentctl rollback --version 1.0.0
systemctl is-active --quiet owndock-agent.service || fail "rolled back service is not active"
wait_for_version 1.0.0
[ "$(tr -d '\r\n' < /var/lib/owndock-agent/systemd-preserved-state)" = preserved-state ] || \
    fail "runtime state changed during rollback"

[ "$(systemctl show owndock-agent.service -p User --value)" = owndock-agent ] || \
    fail "systemd user hardening is missing"
[ "$(systemctl show owndock-agent.service -p NoNewPrivileges --value)" = yes ] || \
    fail "NoNewPrivileges is not active"
[ "$(systemctl show owndock-agent.service -p ProtectSystem --value)" = strict ] || \
    fail "ProtectSystem is not strict"

printf '%s\n' "OwnDock Agent systemd lifecycle integration passed"
