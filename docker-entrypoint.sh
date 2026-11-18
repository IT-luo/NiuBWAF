#!/bin/sh
set -e
mkdir -p /app/data
if [ ! -f /app/data/geoip.mmdb ] && [ -f /app/seed/geoip.mmdb ]; then
    cp /app/seed/geoip.mmdb /app/data/geoip.mmdb
fi
exec /app/niubwaf "$@"