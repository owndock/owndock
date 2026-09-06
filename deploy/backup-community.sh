#!/bin/sh
set -eu

if [ "$#" -ne 1 ] || [ -z "$1" ]; then
  echo "usage: $0 ABSOLUTE_OUTPUT.archive.gz" >&2
  exit 2
fi

output=$1
case "$output" in
  /*.archive.gz) ;;
  *)
    echo "backup output must be an absolute .archive.gz path" >&2
    exit 2
    ;;
esac

parent=$(dirname "$output")
if [ ! -d "$parent" ] || [ -L "$parent" ]; then
  echo "backup parent must be an existing real directory" >&2
  exit 2
fi
if [ -e "$output" ] || [ -L "$output" ] || [ -e "$output.sha256" ] || [ -L "$output.sha256" ]; then
  echo "refusing to replace an existing backup or checksum" >&2
  exit 2
fi
if ! command -v docker >/dev/null 2>&1 || ! command -v openssl >/dev/null 2>&1; then
  echo "docker and openssl are required" >&2
  exit 2
fi

script_directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
compose_file=$script_directory/community.compose.yaml
running=$(docker compose -f "$compose_file" ps --status running --services)
if printf '%s\n' "$running" | grep -qx server; then
  echo "server is running; stop it and all external workers before backup" >&2
  exit 2
fi
if ! printf '%s\n' "$running" | grep -qx mongodb; then
  echo "mongodb is not running" >&2
  exit 2
fi

umask 077
partial=$output.partial.$$
checksum_partial=$output.sha256.partial.$$
cleanup() {
  rm -f "$partial" "$checksum_partial"
}
trap cleanup EXIT HUP INT TERM

docker compose -f "$compose_file" exec -T mongodb \
  mongodump --config /run/secrets/owndock-mongodb-tools-config \
    --db owndock --archive --gzip >"$partial"

if [ ! -s "$partial" ]; then
  echo "mongodump produced an empty archive" >&2
  exit 1
fi
chmod 0600 "$partial"
digest=$(openssl dgst -sha256 "$partial" | awk '{print $NF}')
case "$digest" in
  [0-9a-fA-F][0-9a-fA-F]*) ;;
  *) echo "could not calculate backup SHA-256" >&2; exit 1 ;;
esac
printf '%s  %s\n' "$digest" "$(basename "$output")" >"$checksum_partial"
chmod 0600 "$checksum_partial"
mv "$partial" "$output"
mv "$checksum_partial" "$output.sha256"
trap - EXIT HUP INT TERM

echo "backup created: $output"
echo "checksum created: $output.sha256"
echo "encrypt the archive before copying it outside this host"
