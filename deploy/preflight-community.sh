#!/bin/sh

set -eu

fail() {
    printf '%s: %s\n' preflight-community "$1" >&2
    exit 1
}

[ "$#" -eq 0 ] || fail "arguments are not accepted"
[ "$(uname -s)" = Linux ] || fail "Ubuntu Server 24.04 LTS is required"
case "$(uname -m)" in
    x86_64) architecture=amd64 ;;
    aarch64) architecture=arm64 ;;
    *) fail "linux/amd64 or linux/arm64 is required" ;;
esac
[ -f /etc/os-release ] || fail "OS release identity is unavailable"
os_id=$(awk -F= '$1 == "ID" { gsub(/"/, "", $2); print tolower($2) }' /etc/os-release)
os_version=$(awk -F= '$1 == "VERSION_ID" { gsub(/"/, "", $2); print $2 }' /etc/os-release)
[ "$os_id" = ubuntu ] && [ "$os_version" = 24.04 ] || \
    fail "Ubuntu Server 24.04 LTS is required"
[ -d /run/systemd/system ] || fail "a running systemd system instance is required"
[ -s /sys/fs/cgroup/cgroup.controllers ] || fail "cgroup v2 is required"
[ -x /usr/bin/docker ] && [ ! -L /usr/bin/docker ] || \
    fail "Docker CLI must be a regular executable at /usr/bin/docker"
[ -S /var/run/docker.sock ] && [ ! -L /var/run/docker.sock ] || \
    fail "the local Docker Unix socket is unavailable or unsafe"

docker_engine=$(/usr/bin/docker version --format '{{.Server.Version}}') || \
    fail "Docker Engine is unavailable"
[ "$docker_engine" = 29.6.1 ] || fail "Docker Engine 29.6.1 is required"
docker_api=$(/usr/bin/docker version --format '{{.Server.APIVersion}}') || \
    fail "Docker API version is unavailable"
docker_os=$(/usr/bin/docker info --format '{{.OSType}}') || fail "Docker information is unavailable"
docker_arch=$(/usr/bin/docker info --format '{{.Architecture}}') || fail "Docker architecture is unavailable"
docker_cgroup=$(/usr/bin/docker info --format '{{.CgroupVersion}}') || fail "Docker cgroup mode is unavailable"
[ "$docker_os" = linux ] || fail "a Linux Docker Engine is required"
case "$architecture:$docker_arch" in
    amd64:x86_64|amd64:amd64|arm64:aarch64|arm64:arm64) ;;
    *) fail "Docker Engine architecture does not match the host" ;;
esac
[ "$docker_cgroup" = 2 ] || fail "Docker Engine must use cgroup v2"
/usr/bin/docker compose version >/dev/null 2>&1 || fail "Docker Compose v2 is required"
printf '%s\n' "$docker_api" | grep -Eq '^[0-9A-Za-z._+-]{1,32}$' || \
    fail "Docker API version is invalid"

printf '{"status":"passed","os":"ubuntu","os_version":"24.04","architecture":"%s","docker_engine":"29.6.1","docker_api":"%s","systemd":true,"cgroup_v2":true,"docker_socket":true,"docker_compose":true}\n' \
    "$architecture" "$docker_api"
