FROM python:3.9-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    tcpdump \
    tshark \
    curl \
    net-tools \
    iputils-ping \
    iproute2 \
    libcap2-bin \
    libpcap-dev \
    gcc \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

# Create directories and set up Python environment
RUN mkdir -p /app/captures /app/logs /app/reports && \
    pip install --no-cache-dir --upgrade pip==23.3.1 setuptools==69.0.2 wheel==0.42.0

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --timeout 100 -r requirements.txt

# Copy application files
COPY . .

# Set up application directory and permissions
RUN mkdir -p /app/captures /app/logs /app/reports && \
    chmod 755 /app

# Configure environment
ENV STREAMLIT_SERVER_PORT=8502 \
    STREAMLIT_SERVER_ADDRESS=0.0.0.0 \
    STREAMLIT_SERVER_HEADLESS=true \
    STREAMLIT_SERVER_FILE_WATCHER_TYPE=none \
    NETWATCH_ALLOW_ROOT=1 \
    PYTHONUNBUFFERED=1

# Expose port
EXPOSE 8502

# Set working directory
WORKDIR /app

# Add healthcheck
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8502/_stcore/health || exit 1

# Run the application
ENTRYPOINT ["python3", "-m", "streamlit", "run", "--server.address", "0.0.0.0", "--server.port", "8502", "netwatch.py"]

