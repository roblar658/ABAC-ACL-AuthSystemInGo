# =========================================================================
# Stage 1: Build the Go application
# =========================================================================
FROM golang:1.24-alpine AS builder

WORKDIR /src

# Install build essentials and certs
RUN apk add --no-cache git ca-certificates

# Copy dependency files
COPY go.mod ./
RUN go mod download

# Copy source code
COPY . .

# Build statically linked binary
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-w -s" \
    -o /bin/acl-server ./cmd/server

# =========================================================================
# Stage 2: Minimal runtime image
# =========================================================================
FROM alpine:3.21

WORKDIR /app

# Add ca-certificates and tzdata
RUN apk add --no-cache ca-certificates tzdata

# Create non-root user for security
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

# Copy compiled binary from builder
COPY --from=builder /bin/acl-server /app/acl-server

# Copy static frontend assets
COPY --from=builder /src/web/static /app/web/static

# Permissions
RUN chown -R appuser:appgroup /app
USER appuser

EXPOSE 8080

ENTRYPOINT ["/app/acl-server"]
CMD ["-port", "8080", "-static", "/app/web/static"]
