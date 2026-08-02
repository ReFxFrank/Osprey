# Node 24 runs the TypeScript sources directly (native type stripping), so there
# is no build step and no dist/ to drift from src/. The tsconfig sets
# `erasableSyntaxOnly`, which makes that guarantee mechanical rather than a
# convention: anything Node cannot strip fails `pnpm typecheck`.
FROM node:24-alpine

WORKDIR /app
ENV NODE_ENV=production \
    COREPACK_ENABLE_DOWNLOAD_PROMPT=0

RUN corepack enable

COPY package.json pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile --prod

COPY src ./src
COPY drizzle ./drizzle
COPY sql ./sql

# Runs unprivileged; the relay needs no filesystem writes and no capabilities.
USER node

EXPOSE 8080
CMD ["node", "src/index.ts"]
