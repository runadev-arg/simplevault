# syntax=docker/dockerfile:1.7
# apps/api production image — multi-stage, non-root, migrate-then-start ENTRYPOINT.
# Build context: monorepo root.
#   docker build -f apps/api/Dockerfile -t simplevault-api .
ARG NODE_VERSION=22-alpine

# ---------- deps ----------
FROM node:${NODE_VERSION} AS deps
RUN apk add --no-cache libc6-compat
ENV PNPM_HOME=/pnpm
ENV PATH=$PNPM_HOME:$PATH
RUN corepack enable && corepack prepare pnpm@9.15.0 --activate

WORKDIR /repo
# Manifests + lockfile + workspace config first, for cache efficiency.
COPY pnpm-workspace.yaml pnpm-lock.yaml package.json .npmrc ./
COPY turbo.json tsconfig.base.json ./
COPY packages/tsconfig/ packages/tsconfig/
COPY packages/eslint-config/ packages/eslint-config/
COPY packages/shared/package.json packages/shared/
COPY packages/crypto/package.json packages/crypto/
COPY packages/db/package.json packages/db/
COPY apps/api/package.json apps/api/
COPY patches/ patches/

RUN --mount=type=cache,id=pnpm-store,target=/pnpm/store \
    pnpm install --frozen-lockfile --prod=false

# ---------- build ----------
FROM deps AS build
WORKDIR /repo
COPY packages/shared packages/shared
COPY packages/crypto packages/crypto
COPY packages/db packages/db
COPY apps/api apps/api

RUN pnpm --filter @simplevault/shared build \
 && pnpm --filter @simplevault/crypto build \
 && pnpm --filter @simplevault/db build \
 && pnpm --filter @simplevault/api build

# Prune to a self-contained production bundle at /out (workspace deps inlined).
RUN --mount=type=cache,id=pnpm-store,target=/pnpm/store \
    pnpm --filter @simplevault/api deploy --prod /out

# Make sure the migrations folder is shipped alongside the deployed @simplevault/db.
# `pnpm deploy` copies package files based on the package's `files` field (or all
# tracked files if absent). The drizzle/ folder is required by migrate.js which
# is invoked from the package root with migrationsFolder: "./drizzle".
RUN cp -R /repo/packages/db/drizzle /out/node_modules/@simplevault/db/drizzle

# ---------- runner ----------
FROM node:${NODE_VERSION} AS runner
RUN apk add --no-cache tini curl \
 && addgroup -S app && adduser -S -G app -h /app app

WORKDIR /app
COPY --from=build --chown=app:app /out/node_modules ./node_modules
COPY --from=build --chown=app:app /out/dist ./dist
COPY --from=build --chown=app:app /out/package.json ./package.json
COPY --chown=app:app apps/api/scripts/migrate-then-start.sh ./migrate-then-start.sh
RUN chmod +x ./migrate-then-start.sh

USER app
ENV NODE_ENV=production
ENV PORT=3001

EXPOSE 3001
HEALTHCHECK --interval=20s --timeout=5s --start-period=15s --retries=3 \
  CMD curl -fsS http://localhost:3001/health || exit 1

# tini handles PID 1 + signal forwarding; exec inside the script ensures
# SIGTERM reaches Node directly (clean Postgres pool shutdown).
ENTRYPOINT ["/sbin/tini", "--", "./migrate-then-start.sh"]
