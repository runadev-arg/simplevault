# syntax=docker/dockerfile:1.7
# apps/web production image — Next.js 15 standalone, multi-stage, non-root.
# Build context: monorepo root.
#   docker build -f apps/web/Dockerfile -t simplevault-web .
ARG NODE_VERSION=22-alpine

# ---------- deps ----------
FROM node:${NODE_VERSION} AS deps
RUN apk add --no-cache libc6-compat
ENV PNPM_HOME=/pnpm
ENV PATH=$PNPM_HOME:$PATH
RUN corepack enable && corepack prepare pnpm@9.15.0 --activate

WORKDIR /repo
COPY pnpm-workspace.yaml pnpm-lock.yaml package.json .npmrc ./
COPY turbo.json tsconfig.base.json ./
COPY packages/tsconfig/ packages/tsconfig/
COPY packages/eslint-config/ packages/eslint-config/
COPY packages/shared/package.json packages/shared/
COPY packages/crypto/package.json packages/crypto/
COPY packages/db/package.json packages/db/
COPY apps/web/package.json apps/web/
COPY patches/ patches/

RUN --mount=type=cache,id=pnpm-store,target=/pnpm/store \
    pnpm install --frozen-lockfile --prod=false

# ---------- build ----------
FROM deps AS build
WORKDIR /repo
COPY packages/shared packages/shared
COPY apps/web apps/web

RUN pnpm --filter @simplevault/shared build \
 && pnpm --filter @simplevault/web build

# ---------- runner ----------
FROM node:${NODE_VERSION} AS runner
RUN apk add --no-cache tini curl \
 && addgroup -S app && adduser -S -G app -h /app app

WORKDIR /app
ENV NODE_ENV=production
ENV PORT=3000
ENV HOSTNAME=0.0.0.0

# Next.js standalone output — `outputFileTracingRoot` ensures workspace deps
# (@simplevault/shared) are bundled inside the standalone tree.
COPY --from=build --chown=app:app /repo/apps/web/.next/standalone ./
COPY --from=build --chown=app:app /repo/apps/web/.next/static ./apps/web/.next/static
# No `public/` dir in v1 — revisit when adding favicons / og images.

USER app
EXPOSE 3000
HEALTHCHECK --interval=20s --timeout=5s --start-period=10s --retries=3 \
  CMD curl -fsS http://localhost:3000/ -o /dev/null || exit 1

ENTRYPOINT ["/sbin/tini", "--", "node", "apps/web/server.js"]
