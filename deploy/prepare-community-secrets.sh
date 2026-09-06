#!/bin/sh
set -eu

if [ "$#" -ne 1 ] || [ -z "$1" ]; then
  echo "usage: $0 ABSOLUTE_SECRET_DIRECTORY" >&2
  exit 2
fi

directory=$1
case "$directory" in
  /*) ;;
  *)
    echo "secret directory must be an absolute path" >&2
    exit 2
    ;;
esac

if ! command -v openssl >/dev/null 2>&1; then
  echo "openssl is required" >&2
  exit 2
fi

umask 077
mkdir -p "$directory"
if [ ! -d "$directory" ] || [ -L "$directory" ]; then
  echo "secret directory must be a real directory" >&2
  exit 2
fi
chmod 0700 "$directory"
for name in mongodb-root-username mongodb-root-password mongodb-app-password mongodb-tools-password mongodb-keyfile owndock-bootstrap-token owndock-mongodb-uri owndock-mongodb-tools.yaml; do
  if [ -e "$directory/$name" ] || [ -L "$directory/$name" ]; then
    echo "refusing to replace $directory/$name" >&2
    exit 2
  fi
done

username=owndock-root
password=$(openssl rand -hex 32)
app_password=$(openssl rand -hex 32)
tools_password=$(openssl rand -hex 32)
bootstrap_token=$(openssl rand -hex 32)

printf '%s\n' "$username" >"$directory/mongodb-root-username"
printf '%s\n' "$password" >"$directory/mongodb-root-password"
printf '%s\n' "$app_password" >"$directory/mongodb-app-password"
printf '%s\n' "$tools_password" >"$directory/mongodb-tools-password"
openssl rand -base64 756 >"$directory/mongodb-keyfile"
printf '%s\n' "$bootstrap_token" >"$directory/owndock-bootstrap-token"
printf 'mongodb://%s:%s@mongodb:27017/?replicaSet=rs0&authSource=owndock\n' \
  "owndock-app" "$app_password" >"$directory/owndock-mongodb-uri"
printf 'uri: "mongodb://%s:%s@mongodb:27017/?replicaSet=rs0&authSource=admin"\n' \
  "owndock-tools" "$tools_password" >"$directory/owndock-mongodb-tools.yaml"
chmod 0400 "$directory"/*

echo "community secret files created in $directory"
echo "store the bootstrap token in a password manager, then remove its file after bootstrap"
