# Multi-stage Dockerfile for ryansend
FROM rust:1.92 AS builder

WORKDIR /usr/src/app

# Copy manifests
COPY Cargo.toml ./

# Copy source code
COPY src ./src

# Build the application in release mode
RUN cargo build --release

# Runtime stage - using Debian slim for glibc compatibility
FROM debian:bookworm-slim

# Install CA certificates and create app user
RUN apt-get update && \
    apt-get install -y ca-certificates && \
    rm -rf /var/lib/apt/lists/* && \
    useradd -m -u 1000 appuser

# Copy the binary from builder stage
COPY --from=builder /usr/src/app/target/release/ryansend /usr/local/bin/ryansend

# Make binary executable and create working directory
RUN chmod +x /usr/local/bin/ryansend && \
    mkdir -p /app && \
    chown appuser:appuser /app

# Switch to non-root user
USER appuser
WORKDIR /app

# Expose the default port
EXPOSE 3000

# Default command - will auto-init if no config exists
CMD ["ryansend", "start"]
