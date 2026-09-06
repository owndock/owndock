#!/bin/sh
set -eu

if [ "$#" -ne 1 ] || [ -z "$1" ]; then
  echo "usage: $0 LOCAL_SERVER_IMAGE" >&2
  exit 2
fi
server_image=$1
case "$server_image" in
  owndock-community-integration:*) ;;
  *) echo "integration image must use the isolated owndock-community-integration repository" >&2; exit 2 ;;
esac

for command in docker curl openssl; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "$command is required" >&2
    exit 2
  fi
done
docker compose version >/dev/null

script_directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
compose_file=$script_directory/community.compose.yaml
test_directory=$(mktemp -d)
case "$test_directory" in
  /tmp/*|/private/tmp/*) ;;
  *) echo "unexpected temporary directory: $test_directory" >&2; exit 2 ;;
esac
secret_directory=$test_directory/secrets
backup_directory=$test_directory/backups
project=owndock-community-test-$$
mkdir -m 0700 "$backup_directory"

export COMPOSE_PROJECT_NAME=$project
export OWNDOCK_SERVER_IMAGE=$server_image
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
docker compose -f "$compose_file" up -d

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

if docker compose -f "$compose_file" port mongodb 27017 2>/dev/null | grep -q .; then
  echo "MongoDB unexpectedly exposes a host port" >&2
  exit 1
fi
server_container=$(docker compose -f "$compose_file" ps -q server)
test -n "$server_container"
server_user=$(docker inspect --format '{{.Config.User}}' "$server_container")
case "$server_user" in
  ""|0|0:*|root|root:*) echo "Server is not configured as a non-root container" >&2; exit 1 ;;
esac
test "$(docker inspect --format '{{.HostConfig.ReadonlyRootfs}}' "$server_container")" = true
docker inspect --format '{{join .HostConfig.CapDrop ","}}' "$server_container" | grep -iq all

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

docker compose -f "$compose_file" stop server >/dev/null
archive=$backup_directory/community.archive.gz
sh "$script_directory/backup-community.sh" "$archive" >/dev/null
test -s "$archive"
test -s "$archive.sha256"
docker compose -f "$compose_file" logs --no-color >"$test_directory/compose.log"

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
  sh "$script_directory/restore-community.sh" "$archive" "$archive.sha256" >/dev/null
docker compose -f "$compose_file" up -d server
wait_ready

status=$(curl --silent --show-error --output "$test_directory/restored-login-response.json" --write-out '%{http_code}' \
  --request POST --header 'Content-Type: application/json' --data-binary "@$login_body" \
  "http://127.0.0.1:$OWNDOCK_HTTP_PORT/api/v1/auth/login")
test "$status" = 200

docker compose -f "$compose_file" logs --no-color >>"$test_directory/compose.log"
for secret_file in \
  mongodb-root-password mongodb-app-password mongodb-tools-password \
  owndock-bootstrap-token owndock-mongodb-uri owndock-mongodb-tools.yaml; do
  secret_value=$(tr -d '\r\n' <"$secret_directory/$secret_file")
  if [ -n "$secret_value" ] && grep -Fq "$secret_value" "$test_directory/compose.log"; then
    echo "Compose logs exposed $secret_file" >&2
    exit 1
  fi
done
if grep -Fq 'integration-password-123' "$test_directory/compose.log"; then
  echo "Compose logs exposed the integration login password" >&2
  exit 1
fi

echo "community startup, persistence, backup and empty-volume restore passed"
