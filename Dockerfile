FROM python:3.9-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    tcpdump=4.99.1-3 \
    tshark=3.4.9-1 \
    curl=7.74.0-1.3+deb11u11 \
    net-tools=1.60+git20181103.0eebece-1 \
    iputils-ping=3:20210202-1 \
    iproute2=5.10.0-4 \
    libcap2-bin=1:2.44-1 \
    libpcap-dev=1.10.0-2 \
    gcc=4:10.2.1-1 \
    python3-dev=3.9.2-3 \
    && rm -rf /var/lib/apt/lists/*

# Create directories and set up Python environment
RUN mkdir -p /app/captures /app/logs /app/reports && \
    pip install --no-cache-dir --upgrade pip==23.3.1 setuptools==69.0.2 wheel==0.42.0

# Install Python dependencies
COPY requirements.txt .
# Install all Python dependencies in one layer to reduce image size
RUN pip install --no-cache-dir --timeout 100 \
    streamlit==1.27.0 \
    scapy==2.5.0 \
    pandas==2.1.0 \
    plotly==5.17.0 \
    python-dotenv==1.0.0 \
    aiohttp==3.9.1 \
    requests==2.31.0 \
    slack-sdk==3.26.0 \
    pyshark==0.6.0 \
    psutil==5.9.6 \
    dnspython==2.4.2 \
    pypcap==1.3.0 \
    netifaces==0.11.0 \
    cryptography==41.0.7 \
    pyOpenSSL==23.3.0

# Copy application files
COPY . .

# Set permissions for network tools and create non-root user
RUN setcap cap_net_raw,cap_net_admin=eip /usr/bin/tcpdump && \
    setcap cap_net_raw,cap_net_admin=eip /usr/bin/tshark && \
    setcap cap_net_raw,cap_net_admin=eip /usr/local/bin/python3.9 && \
    useradd -m -s /bin/bash netwatch && \
    chown -R netwatch:netwatch /app

# Configure environment
ENV STREAMLIT_SERVER_PORT=8502 \
    STREAMLIT_SERVER_ADDRESS=0.0.0.0 \
    STREAMLIT_SERVER_HEADLESS=true \
    STREAMLIT_SERVER_FILE_WATCHER_TYPE=none \
    NETWATCH_ALLOW_ROOT=1 \
    PYTHONUNBUFFERED=1

# Expose port
EXPOSE 8502

# Switch to non-root user
USER netwatch

# Add healthcheck
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8502/_stcore/health || exit 1

# Run the application with network capabilities
ENTRYPOINT ["python3", "-m", "streamlit", "run", "netwatch.py"]
CMD ["--server.address=0.0.0.0", "--server.port=8502"]
