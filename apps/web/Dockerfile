# syntax=docker/dockerfile:1@sha256:ecfaec9ed6d810b56388c508f4121597bfbba70d41a6dfeee4d8cad5f295fc32

# Tag and digest together: the digest pins the build, the tag stays legible and
# both are what the dependency updater reads.
FROM node:24-alpine@sha256:e67514e5d0f6c46656005e1b693b2ec9d52e80b641307de684d4a015ba7a4eaf AS dependencies
WORKDIR /repository
ENV COREPACK_ENABLE_DOWNLOAD_PROMPT=0 NEXT_TELEMETRY_DISABLED=1

# Manifests first, so a source-only change does not reinstall the workspace.
COPY package.json pnpm-workspace.yaml pnpm-lock.yaml ./
COPY apps/web/package.json apps/web/
RUN corepack enable pnpm && pnpm install --frozen-lockfile

# Named copies rather than the whole tree, so nothing arrives by accident.
FROM dependencies AS source
COPY apps/web/ apps/web/

# A regression guard: should a broad copy ever come back, this stops the build.
RUN for path in design docs ROADMAP.md CLAUDE.md AGENTS.md .claude audit; do \
      if [ -e "$path" ] || [ -e "apps/web/$path" ]; then \
        echo "private path reached the build stage: $path" >&2; exit 1; \
      fi; \
    done

# Development only: the same sources, served by the framework's own server. The
# workspace is handed to the unprivileged user so watched files stay writable.
FROM source AS development
RUN chown -R node:node /repository
USER node
WORKDIR /repository/apps/web
EXPOSE 3000
CMD ["pnpm", "exec", "next", "dev", "--hostname", "0.0.0.0", "--port", "3000"]

FROM source AS build
# Only the public name is required; the API rewrite is opt-in and unset here.
ARG SITE_NAME
ENV SITE_NAME=${SITE_NAME}
RUN pnpm --filter @app/web build

FROM node:24-alpine@sha256:e67514e5d0f6c46656005e1b693b2ec9d52e80b641307de684d4a015ba7a4eaf AS runtime
WORKDIR /application
ENV NODE_ENV=production NEXT_TELEMETRY_DISABLED=1 HOSTNAME=0.0.0.0 PORT=3000

# The traced server carries its own dependencies; the static assets do not.
COPY --from=build /repository/apps/web/.next/standalone ./
COPY --from=build /repository/apps/web/.next/static ./apps/web/.next/static

USER node
EXPOSE 3000
CMD ["node", "apps/web/server.js"]
