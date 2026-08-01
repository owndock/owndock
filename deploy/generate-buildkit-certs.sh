#!/bin/sh
set -eu

if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
  echo "usage: $0 OUTPUT_DIRECTORY [SERVER_DNS_NAME]" >&2
  exit 2
fi

output_directory=$1
server_name=${2:-buildkit}
case "$output_directory" in
  /*) ;;
  *) echo "OUTPUT_DIRECTORY must be absolute" >&2; exit 2 ;;
esac
case "$server_name" in
  *[!A-Za-z0-9.-]*|'') echo "SERVER_DNS_NAME is invalid" >&2; exit 2 ;;
esac
if [ -d "$output_directory" ] && [ -n "$(ls -A "$output_directory" 2>/dev/null)" ]; then
  echo "OUTPUT_DIRECTORY must be empty" >&2
  exit 2
fi

umask 077
mkdir -p "$output_directory"

openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$output_directory/ca-key.pem"
openssl req -x509 -new -sha256 -days 3650 \
  -key "$output_directory/ca-key.pem" -out "$output_directory/ca.pem" \
  -subj "/CN=OwnDock BuildKit CA"

issue_certificate() {
  name=$1
  common_name=$2
  extended_usage=$3
  subject_alt_name=$4
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$output_directory/$name-key.pem"
  openssl req -new -sha256 -key "$output_directory/$name-key.pem" \
    -out "$output_directory/$name.csr" -subj "/CN=$common_name"
  extension_file="$output_directory/$name.ext"
  {
    echo "basicConstraints=critical,CA:FALSE"
    echo "keyUsage=critical,digitalSignature,keyEncipherment"
    echo "extendedKeyUsage=$extended_usage"
    if [ -n "$subject_alt_name" ]; then
      echo "subjectAltName=$subject_alt_name"
    fi
  } > "$extension_file"
  openssl x509 -req -sha256 -days 825 \
    -in "$output_directory/$name.csr" \
    -CA "$output_directory/ca.pem" -CAkey "$output_directory/ca-key.pem" -CAcreateserial \
    -extfile "$extension_file" -out "$output_directory/$name-cert.pem"
  rm -f "$output_directory/$name.csr" "$extension_file"
}

issue_certificate server "$server_name" serverAuth "DNS:$server_name"
issue_certificate worker owndock-build-worker clientAuth ""
chmod 0600 "$output_directory"/*-key.pem
chmod 0644 "$output_directory"/*-cert.pem "$output_directory/ca.pem"

echo "BuildKit mTLS material created in $output_directory"
echo "Keep ca-key.pem offline; do not mount it into BuildKit or Build Worker."
if [ "$(id -u)" != "1000" ]; then
  echo "Before Linux deployment, copy the mounted certificate/key files with owner 1000 and preserve 0600 key permissions."
fi
