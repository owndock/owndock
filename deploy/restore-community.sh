#!/bin/sh
set -eu

if [ "$#" -ne 2 ] || [ -z "$1" ] || [ -z "$2" ]; then
  echo "usage: $0 ABSOLUTE_INPUT.archive.gz ABSOLUTE_INPUT.archive.gz.sha256" >&2
  exit 2
fi
if [ "${OWNDOCK_RESTORE_CONFIRM:-}" != "empty-owndock-database" ]; then
  echo "set OWNDOCK_RESTORE_CONFIRM=empty-owndock-database for an intentional restore" >&2
  exit 2
fi

archive=$1
checksum=$2
case "$archive:$checksum" in
  /*.archive.gz:/*.archive.gz.sha256) ;;
  *) echo "archive and checksum paths must be absolute and use the expected suffixes" >&2; exit 2 ;;
esac
for path in "$archive" "$checksum"; do
  if [ ! -f "$path" ] || [ -L "$path" ]; then
    echo "restore inputs must be regular files, not symlinks" >&2
    exit 2
  fi
  permissions=$(stat -f '%Lp' "$path" 2>/dev/null || stat -c '%a' "$path")
  case "$permissions" in
    *[2367]?|*?[2367]) echo "restore inputs must not be group/world writable" >&2; exit 2 ;;
  esac
done
if ! command -v docker >/dev/null 2>&1 || ! command -v openssl >/dev/null 2>&1; then
  echo "docker and openssl are required" >&2
  exit 2
fi

expected=$(awk 'NF == 2 { print $1; exit }' "$checksum")
actual=$(openssl dgst -sha256 "$archive" | awk '{print $NF}')
if [ -z "$expected" ] || [ "$expected" != "$actual" ]; then
  echo "backup SHA-256 verification failed" >&2
  exit 1
fi

script_directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
compose_file=$script_directory/community.compose.yaml
running=$(docker compose -f "$compose_file" ps --status running --services)
if printf '%s\n' "$running" | grep -qx server; then
  echo "server is running; stop it and all external workers before restore" >&2
  exit 2
fi
if ! printf '%s\n' "$running" | grep -qx mongodb; then
  echo "mongodb is not running" >&2
  exit 2
fi

collection_count=$(docker compose -f "$compose_file" exec -T mongodb sh -eu -c '
  username=$(tr -d "\r\n" </run/secrets/mongodb-root-username)
  password=$(tr -d "\r\n" </run/secrets/mongodb-root-password)
  test -n "$username"
  test -n "$password"
  mongosh --quiet --host mongodb:27017 \
    --username "$username" --password "$password" \
    --authenticationDatabase admin --eval '\''
    db.getSiblingDB("owndock").getCollectionNames()
      .filter(name => !name.startsWith("system.")).length
  '\''
')
if [ "$collection_count" != "0" ]; then
  echo "target owndock database is not empty; restore is refused" >&2
  exit 2
fi

docker compose -f "$compose_file" exec -T mongodb \
  mongorestore --config /run/secrets/owndock-mongodb-tools-config \
    --archive --gzip --nsInclude 'owndock.*' --stopOnError <"$archive"

echo "restore completed; start the backed-up OwnDock version and run validation"
