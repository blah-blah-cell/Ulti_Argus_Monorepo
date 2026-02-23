# Stage 1: Builder
FROM python:3.11-slim as builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    git \
    && rm -rf /var/lib/apt/lists/*

# Copy the project files
COPY Ulti_argus /app/Ulti_argus

# Install dependencies and the package into a temporary directory
# We use --prefix to easily copy everything to the runtime image
RUN pip install --no-cache-dir --prefix=/install /app/Ulti_argus

# Stage 2: Runtime
FROM python:3.11-slim

WORKDIR /app

# Install runtime dependencies (e.g. libpcap for scapy, curl for healthcheck)
RUN apt-get update && apt-get install -y \
    libpcap0.8 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy installed python packages from builder
COPY --from=builder /install /usr/local

# Copy example config
COPY Ulti_argus/aegis-config.example.yaml /etc/argus/aegis.example.yaml

# Create necessary directories
RUN mkdir -p /etc/argus \
    /var/lib/argus/models \
    /var/lib/argus/scalers \
    /var/lib/argus/retina/csv \
    /var/lib/argus/aegis \
    /var/run/argus

# Copy entrypoint script
COPY scripts/docker-entrypoint.sh /scripts/docker-entrypoint.sh
RUN chmod +x /scripts/docker-entrypoint.sh

# Environment variables
ENV PYTHONPATH=/usr/local/lib/python3.11/site-packages
ENV ARGUS_CONFIG_FILE=/etc/argus/aegis.yaml

# Expose ports
# 8081: FastAPI
# 9090: Prometheus Metrics
EXPOSE 8081 9090

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
  CMD curl -f http://localhost:8081/api/status || exit 1

# Entrypoint
ENTRYPOINT ["/scripts/docker-entrypoint.sh"]
