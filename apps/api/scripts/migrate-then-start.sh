#!/bin/sh
# migrate-then-start.sh — runs Drizzle migrations, then exec's the API.
# Idempotent: drizzle-orm tracks applied migrations in __drizzle_migrations.
# Fail-fast: any non-zero exit aborts startup so the container is restarted
# without running a stale schema against the new code.
set -eu

echo "[startup] Running drizzle migrations..."

# The migrate runner lives inside the deployed @simplevault/db package.
# We `cd` there so the relative `./drizzle` migrationsFolder resolves to
# the migrations directory we copied alongside the package.
cd /app/node_modules/@simplevault/db
node ./dist/migrate.js
cd /app

echo "[startup] Migrations applied. Starting api..."
exec node dist/main.js
