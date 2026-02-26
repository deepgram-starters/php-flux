# Stage 1: Build custom Caddy with rate limiting module
FROM golang:1.25-alpine AS caddy-builder
WORKDIR /build
RUN go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest
RUN xcaddy build --with github.com/mholt/caddy-ratelimit
# Binary output: /build/caddy

# Stage 2: Build frontend
FROM node:24-slim AS frontend-builder
RUN corepack enable
WORKDIR /build
COPY frontend/package.json frontend/pnpm-lock.yaml ./frontend/
RUN cd frontend && pnpm install --frozen-lockfile
COPY frontend/ ./frontend/
RUN cd frontend && pnpm build
# Inject Caddy template directive for subpath base path
RUN sed -i 's|<head>|<head>\n  <base href="{{ .Req.Header.Get "X-Base-Path" }}">|' ./frontend/dist/index.html

# Stage 3: Install PHP dependencies
FROM php:8.3-cli-alpine AS php-builder
WORKDIR /build
# Install composer
COPY --from=composer:2 /usr/bin/composer /usr/bin/composer
# Install build dependencies for native extensions required by Ratchet
RUN apk add --no-cache autoconf g++ make linux-headers
# Copy composer manifest and install production dependencies
COPY composer.json ./
RUN composer install --no-dev --no-interaction --optimize-autoloader

# Stage 4: Runtime
FROM php:8.3-cli-alpine

# Install pcntl and sockets extensions required by Ratchet/ReactPHP
RUN apk add --no-cache autoconf g++ make linux-headers && \
    docker-php-ext-install pcntl sockets && \
    apk del autoconf g++ make linux-headers

# Copy custom Caddy binary
COPY --from=caddy-builder /build/caddy /usr/bin/caddy

WORKDIR /app

# Copy PHP vendor directory from builder
COPY --from=php-builder /build/vendor/ ./vendor/

# Copy application files
COPY server.php deepgram.toml sample.env ./

# Copy built frontend
COPY --from=frontend-builder /build/frontend/dist/ ./frontend/dist/

# Copy deployment files
COPY deploy/Caddyfile /etc/caddy/Caddyfile
COPY deploy/start.sh ./start.sh
RUN chmod +x ./start.sh

ENV BACKEND_CMD="php /app/server.php"
EXPOSE 8080

CMD ["./start.sh"]
