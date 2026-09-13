#!/bin/sh
set -eu

username=$(tr -d '\r\n' </run/secrets/mongodb-root-username)
password=$(tr -d '\r\n' </run/secrets/mongodb-root-password)
app_password=$(tr -d '\r\n' </run/secrets/mongodb-app-password)
tools_password=$(tr -d '\r\n' </run/secrets/mongodb-tools-password)
test -n "$username"
test -n "$password"
test -n "$app_password"
test -n "$tools_password"
for generated_password in "$app_password" "$tools_password"; do
  test "${#generated_password}" -eq 64
  test -z "$(printf '%s' "$generated_password" | tr -d '0-9a-f')"
done

attempt=0
while [ "$attempt" -lt 60 ]; do
  if mongosh --quiet --host mongodb:27017 \
    --username "$username" \
    --password "$password" \
    --authenticationDatabase admin \
    --eval '
      try {
        const status = rs.status();
        if (status.ok === 1) quit(0);
      } catch (error) {
        if (error.codeName !== "NotYetInitialized") quit(2);
      }
      const result = rs.initiate({
        _id: "rs0",
        members: [{_id: 0, host: "mongodb:27017"}]
      });
      if (result.ok !== 1 && result.codeName !== "AlreadyInitialized") quit(2);
    ' >/dev/null 2>&1; then
    break
  fi
  attempt=$((attempt + 1))
  sleep 1
done
test "$attempt" -lt 60

attempt=0
while [ "$attempt" -lt 60 ]; do
  if mongosh --quiet --host mongodb:27017 \
    --username "$username" \
    --password "$password" \
    --authenticationDatabase admin \
    --eval 'quit(db.hello().isWritablePrimary ? 0 : 2)' \
    >/dev/null 2>&1; then
    break
  fi
  attempt=$((attempt + 1))
  sleep 1
done
test "$attempt" -lt 60

# Keep the storage feature set explicit instead of inheriting a value from an
# existing data volume or a future image default. Changing this value is an
# upgrade operation and must be reviewed together with the server image.
mongosh --quiet --host mongodb:27017 \
  --username "$username" \
  --password "$password" \
  --authenticationDatabase admin \
  --eval '
    const expected = "8.3";
    const setResult = db.adminCommand({
      setFeatureCompatibilityVersion: expected,
      confirm: true
    });
    if (setResult.ok !== 1) quit(2);
    const current = db.adminCommand({
      getParameter: 1,
      featureCompatibilityVersion: 1
    });
    quit(current.ok === 1 &&
      current.featureCompatibilityVersion.version === expected ? 0 : 2);
  ' >/dev/null

if ! mongosh --quiet --host mongodb:27017 \
  --username "$username" \
  --password "$password" \
  --authenticationDatabase admin \
  --eval 'quit(db.getSiblingDB("owndock").getUser("owndock-app") ? 0 : 3)' \
  >/dev/null 2>&1; then
  printf '%s\n' \
    'db = db.getSiblingDB("owndock");' \
    'db.createUser({' \
    '  user: "owndock-app",' \
    "  pwd: \"$app_password\"," \
    '  roles: [{role: "readWrite", db: "owndock"}]' \
    '});' | mongosh --quiet --host mongodb:27017 \
      --username "$username" \
      --password "$password" \
      --authenticationDatabase admin >/dev/null
fi

if ! mongosh --quiet --host mongodb:27017 \
  --username "$username" \
  --password "$password" \
  --authenticationDatabase admin \
  --eval 'quit(db.getSiblingDB("admin").getUser("owndock-tools") ? 0 : 3)' \
  >/dev/null 2>&1; then
  printf '%s\n' \
    'db = db.getSiblingDB("admin");' \
    'db.createUser({' \
    '  user: "owndock-tools",' \
    "  pwd: \"$tools_password\"," \
    '  roles: [' \
    '    {role: "backup", db: "admin"},' \
    '    {role: "restore", db: "admin"}' \
    '  ]' \
    '});' | mongosh --quiet --host mongodb:27017 \
      --username "$username" \
      --password "$password" \
      --authenticationDatabase admin >/dev/null
fi

mongosh --quiet --host mongodb:27017 \
  --username owndock-app \
  --password "$app_password" \
  --authenticationDatabase owndock \
  --eval 'quit(db.getSiblingDB("owndock").runCommand({ping: 1}).ok === 1 ? 0 : 2)' \
  >/dev/null

mongosh --quiet --host mongodb:27017 \
  --username owndock-tools \
  --password "$tools_password" \
  --authenticationDatabase admin \
  --eval 'quit(db.getSiblingDB("admin").runCommand({connectionStatus: 1}).ok === 1 ? 0 : 2)' \
  >/dev/null
