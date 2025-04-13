# Use Python 3.9 slim as base image
FROM python:3.9-slim AS builder

# Set working directory
WORKDIR /app

# Install build dependencies and security updates
RUN apt-get update && apt-get upgrade -y && \
    apt-get install -y --no-install-recommends \
    build-essential \
    python3-dev

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Final stage
FROM python:3.9-slim

# Create non-root user
RUN groupadd -r netwatch && \
    useradd -r -g netwatch -s /sbin/nologin -d /app netwatch

# Set working directory
WORKDIR /app

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    tcpdump \
    tshark \
    curl \
    net-tools \
    iputils-ping \
    iproute2 \
    libcap2-bin \
    && rm -rf /var/lib/apt/lists/*

# Create necessary directories with proper permissions
RUN mkdir -p /app/captures /app/logs /app/reports /app/assets && \
    chown -R netwatch:netwatch /app

# Copy Python packages from builder
COPY --from=builder /usr/local/lib/python3.9/site-packages /usr/local/lib/python3.9/site-packages

# Copy application files
COPY --chown=netwatch:netwatch . .

# Set permissions for network tools
RUN setcap cap_net_raw,cap_net_admin=eip /usr/bin/tcpdump && \
    setcap cap_net_raw,cap_net_admin=eip /usr/bin/tshark

# Configure environment
ENV PATH="/usr/local/bin:$PATH" \
    STREAMLIT_SERVER_PORT=8502 \
    STREAMLIT_SERVER_ADDRESS=0.0.0.0 \
    STREAMLIT_SERVER_HEADLESS=true \
    STREAMLIT_SERVER_ENABLE_CORS=false \
    STREAMLIT_BROWSER_GATHER_USAGE_STATS=false \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# Switch to non-root user
USER netwatch

# Expose Streamlit port
EXPOSE 8502

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8502/_stcore/health || exit 1

# Run the application
ENTRYPOINT ["/usr/local/bin/python", "-m", "streamlit", "run", "netwatch.py", \
    "--server.address=0.0.0.0", \
    "--server.port=8502", \
    "--browser.serverAddress=0.0.0.0", \
    "--server.enableCORS=false", \
    "--server.enableXsrfProtection=false"]
