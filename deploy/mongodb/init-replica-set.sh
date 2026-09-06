#!/bin/sh
set -eu

username=$(tr -d '\r\n' </run/secrets/mongodb-root-username)
password=$(tr -d '\r\n' </run/secrets/mongodb-root-password)
test -n "$username"
test -n "$password"

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
    exit 0
  fi
  attempt=$((attempt + 1))
  sleep 1
done

exit 1
