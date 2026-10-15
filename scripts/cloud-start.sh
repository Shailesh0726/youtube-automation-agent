#!/bin/sh
set -eu
# One Railway volume preserves credentials, SQLite and generated media.
for folder in config data logs temp uploads; do
  mkdir -p "/storage/$folder"
  if [ -d "/app/$folder" ] && [ ! -L "/app/$folder" ]; then
    cp -an "/app/$folder/." "/storage/$folder/"
    rm -rf "/app/$folder"
  fi
  ln -sfn "/storage/$folder" "/app/$folder"
done
chmod 700 /storage/config
exec node index.js
