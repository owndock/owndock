#!/bin/sh
set -eu

if [ "$#" -ne 4 ] || [ -z "$1" ] || [ -z "$2" ] || [ -z "$3" ] || [ -z "$4" ]; then
  echo "usage: $0 BASELINE_SERVER_IMAGE BASELINE_VERSION CANDIDATE_SERVER_IMAGE CANDIDATE_VERSION" >&2
  exit 2
fi
baseline_image=$1
baseline_version=$2
candidate_image=$3
candidate_version=$4
for server_image in "$baseline_image" "$candidate_image"; do
  case "$server_image" in
    owndock-community-integration:*) ;;
    ghcr.io/owndock/owndock@sha256:*)
      digest=${server_image#ghcr.io/owndock/owndock@sha256:}
      printf '%s\n' "$digest" | grep -Eq '^[0-9a-f]{64}$' || {
        echo "published integration images must use an exact SHA-256 digest" >&2
        exit 2
      }
      ;;
    *) echo "integration images must use the isolated local repository or the exact published OwnDock digest" >&2; exit 2 ;;
  esac
done
[ "$baseline_image" != "$candidate_image" ] || {
  echo "baseline and candidate images must be different" >&2
  exit 2
}
for server_version in "$baseline_version" "$candidate_version"; do
  printf '%s\n' "$server_version" |
    grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$' || {
      echo "integration versions must use SemVer without a v prefix" >&2
      exit 2
    }
done
[ "$baseline_version" != "$candidate_version" ] || {
  echo "baseline and candidate versions must be different" >&2
  exit 2
}

for command in docker curl openssl; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "$command is required" >&2
    exit 2
  fi
done
docker compose version >/dev/null

script_directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
compose_file=$script_directory/community.compose.yaml
temporary_root=$(CDPATH= cd -- "${TMPDIR:-/tmp}" && pwd -P)
test_directory=$(mktemp -d "$temporary_root/owndock-community.XXXXXX")
case "$test_directory" in
  "$temporary_root"/owndock-community.*) ;;
  *) echo "unexpected temporary directory: $test_directory" >&2; exit 2 ;;
esac
secret_directory=$test_directory/secrets
backup_directory=$test_directory/backups
project=owndock-community-test-$$
mkdir -m 0700 "$backup_directory"

export COMPOSE_PROJECT_NAME=$project
export OWNDOCK_SERVER_IMAGE=$baseline_image
export OWNDOCK_HTTP_PORT=$((18000 + ($$ % 20000)))
export OWNDOCK_MONGODB_KEYFILE_PATH=$secret_directory/mongodb-keyfile
export OWNDOCK_MONGODB_ROOT_USERNAME_PATH=$secret_directory/mongodb-root-username
export OWNDOCK_MONGODB_ROOT_PASSWORD_PATH=$secret_directory/mongodb-root-password
export OWNDOCK_MONGODB_APP_PASSWORD_PATH=$secret_directory/mongodb-app-password
export OWNDOCK_MONGODB_TOOLS_PASSWORD_PATH=$secret_directory/mongodb-tools-password
export OWNDOCK_BOOTSTRAP_TOKEN_PATH=$secret_directory/owndock-bootstrap-token
export OWNDOCK_MONGODB_URI_PATH=$secret_directory/owndock-mongodb-uri
export OWNDOCK_MONGODB_TOOLS_CONFIG_PATH=$secret_directory/owndock-mongodb-tools.yaml

cleanup() {
  docker compose -f "$compose_file" down --volumes --remove-orphans >/dev/null 2>&1 || true
  rm -rf "$test_directory"
}
trap cleanup EXIT HUP INT TERM

sh "$script_directory/prepare-community-secrets.sh" "$secret_directory" >/dev/null
if ! docker compose -f "$compose_file" up -d; then
  docker compose -f "$compose_file" ps -a >&2 || true
  docker compose -f "$compose_file" logs --no-color --tail 100 >&2 || true
  exit 1
fi

wait_ready() {
  attempt=0
  while [ "$attempt" -lt 90 ]; do
    if curl --fail --silent --show-error \
      "http://127.0.0.1:$OWNDOCK_HTTP_PORT/readyz" >/dev/null 2>&1; then
      return 0
    fi
    attempt=$((attempt + 1))
    sleep 1
  done
  docker compose -f "$compose_file" ps >&2 || true
  docker compose -f "$compose_file" logs --no-color --tail 100 >&2 || true
  return 1
}
wait_ready

compose_log=$test_directory/compose.log
: >"$compose_log"
append_compose_logs() {
  docker compose -f "$compose_file" logs --no-color >>"$compose_log"
}

assert_version() {
  expected_version=$1
  response_file=$test_directory/version-response.json
  status=$(curl --silent --show-error --output "$response_file" --write-out '%{http_code}' \
    "http://127.0.0.1:$OWNDOCK_HTTP_PORT/api/v1/meta/version")
  test "$status" = 200
  grep -Fq "\"version\":\"$expected_version\"" "$response_file"
}

assert_server_hardening() {
  server_container=$(docker compose -f "$compose_file" ps -q server)
  test -n "$server_container"
  server_user=$(docker inspect --format '{{.Config.User}}' "$server_container")
  case "$server_user" in
    ""|0|0:*|root|root:*) echo "Server is not configured as a non-root container" >&2; exit 1 ;;
  esac
  test "$(docker inspect --format '{{.HostConfig.ReadonlyRootfs}}' "$server_container")" = true
  docker inspect --format '{{join .HostConfig.CapDrop ","}}' "$server_container" | grep -iq all
}

recreate_server() {
  next_image=$1
  expected_version=$2
  append_compose_logs
  export OWNDOCK_SERVER_IMAGE=$next_image
  if ! docker compose -f "$compose_file" up -d --no-deps --force-recreate server; then
    docker compose -f "$compose_file" ps -a >&2 || true
    docker compose -f "$compose_file" logs --no-color --tail 100 >&2 || true
    return 1
  fi
  wait_ready
  assert_version "$expected_version"
  assert_server_hardening
}

mongodb_container=$(docker compose -f "$compose_file" ps -q mongodb)
test -n "$mongodb_container"
port_bindings=$(docker inspect --format '{{json .HostConfig.PortBindings}}' "$mongodb_container")
case "$port_bindings" in
  null|'{}') ;;
  *) echo "MongoDB unexpectedly exposes a host port: $port_bindings" >&2; exit 1 ;;
esac
assert_version "$baseline_version"
assert_server_hardening

bootstrap_header=$test_directory/bootstrap-header
bootstrap_body=$test_directory/bootstrap.json
bootstrap_response=$test_directory/bootstrap-response.json
login_body=$test_directory/login.json
umask 077
printf 'X-OwnDock-Bootstrap-Token: %s\n' \
  "$(tr -d '\r\n' <"$OWNDOCK_BOOTSTRAP_TOKEN_PATH")" >"$bootstrap_header"
printf '%s\n' \
  '{"organization_name":"OwnDock Integration","email":"owner@example.com","password":"integration-password-123"}' \
  >"$bootstrap_body"
printf '%s\n' \
  '{"email":"owner@example.com","password":"integration-password-123"}' \
  >"$login_body"

status=$(curl --silent --show-error --output "$bootstrap_response" --write-out '%{http_code}' \
  --request POST --header "@$bootstrap_header" --header 'Content-Type: application/json' \
  --data-binary "@$bootstrap_body" \
  "http://127.0.0.1:$OWNDOCK_HTTP_PORT/api/v1/auth/bootstrap")
test "$status" = 201
grep -q '"access_token"' "$bootstrap_response"

status=$(curl --silent --show-error --output /dev/null --write-out '%{http_code}' \
  --request POST --header "@$bootstrap_header" --header 'Content-Type: application/json' \
  --data-binary "@$bootstrap_body" \
  "http://127.0.0.1:$OWNDOCK_HTTP_PORT/api/v1/auth/bootstrap")
test "$status" = 409

docker compose -f "$compose_file" restart server >/dev/null
wait_ready
status=$(curl --silent --show-error --output "$test_directory/login-response.json" --write-out '%{http_code}' \
  --request POST --header 'Content-Type: application/json' --data-binary "@$login_body" \
  "http://127.0.0.1:$OWNDOCK_HTTP_PORT/api/v1/auth/login")
test "$status" = 200

recreate_server "$candidate_image" "$candidate_version"
status=$(curl --silent --show-error --output "$test_directory/upgraded-login-response.json" --write-out '%{http_code}' \
  --request POST --header 'Content-Type: application/json' --data-binary "@$login_body" \
  "http://127.0.0.1:$OWNDOCK_HTTP_PORT/api/v1/auth/login")
test "$status" = 200

recreate_server "$baseline_image" "$baseline_version"
status=$(curl --silent --show-error --output "$test_directory/rollback-login-response.json" --write-out '%{http_code}' \
  --request POST --header 'Content-Type: application/json' --data-binary "@$login_body" \
  "http://127.0.0.1:$OWNDOCK_HTTP_PORT/api/v1/auth/login")
test "$status" = 200

docker compose -f "$compose_file" stop server >/dev/null
archive=$backup_directory/community.archive.gz
if ! sh "$script_directory/backup-community.sh" "$archive" \
  >"$test_directory/backup-command.log" 2>&1; then
  cat "$test_directory/backup-command.log" >&2
  exit 1
fi
test -s "$archive"
test -s "$archive.sha256"
append_compose_logs

docker compose -f "$compose_file" down --volumes --remove-orphans >/dev/null
docker compose -f "$compose_file" up -d mongodb-init
init_container=$(docker compose -f "$compose_file" ps -aq mongodb-init)
test -n "$init_container"
attempt=0
while [ "$attempt" -lt 90 ]; do
  init_state=$(docker inspect --format '{{.State.Status}}:{{.State.ExitCode}}' "$init_container")
  case "$init_state" in
    exited:0) break ;;
    exited:*) echo "MongoDB initialization failed with $init_state" >&2; exit 1 ;;
  esac
  attempt=$((attempt + 1))
  sleep 1
done
test "$init_state" = exited:0
OWNDOCK_RESTORE_CONFIRM=empty-owndock-database \
  sh "$script_directory/restore-community.sh" "$archive" "$archive.sha256" \
    >"$test_directory/restore-command.log" 2>&1 || {
      cat "$test_directory/restore-command.log" >&2
      exit 1
    }
docker compose -f "$compose_file" up -d --no-deps server
wait_ready
assert_version "$baseline_version"
assert_server_hardening

status=$(curl --silent --show-error --output "$test_directory/restored-login-response.json" --write-out '%{http_code}' \
  --request POST --header 'Content-Type: application/json' --data-binary "@$login_body" \
  "http://127.0.0.1:$OWNDOCK_HTTP_PORT/api/v1/auth/login")
test "$status" = 200

append_compose_logs
for secret_file in \
  mongodb-root-password mongodb-app-password mongodb-tools-password \
  owndock-bootstrap-token owndock-mongodb-uri owndock-mongodb-tools.yaml; do
  secret_value=$(tr -d '\r\n' <"$secret_directory/$secret_file")
  if [ -n "$secret_value" ] && grep -Fq "$secret_value" "$compose_log"; then
    echo "Compose logs exposed $secret_file" >&2
    exit 1
  fi
done
if grep -Fq 'integration-password-123' "$compose_log"; then
  echo "Compose logs exposed the integration login password" >&2
  exit 1
fi

echo "community startup, upgrade, rollback, persistence, backup and empty-volume restore passed"
