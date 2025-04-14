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

# Create directories
RUN mkdir -p /app/captures /app/logs /app/reports

# Upgrade pip and install build tools
RUN pip install --no-cache-dir --upgrade pip setuptools wheel

# Install Python dependencies in multiple steps to handle timeouts
COPY requirements.txt .
RUN pip install --no-cache-dir --timeout 100 \
    streamlit==1.27.0 \
    scapy==2.5.0 \
    pandas==2.1.0 \
    plotly==5.17.0 \
    python-dotenv==1.0.0

RUN pip install --no-cache-dir --timeout 100 \
    aiohttp==3.9.1 \
    requests==2.31.0 \
    slack-sdk==3.26.0 \
    pyshark==0.6.0

RUN pip install --no-cache-dir --timeout 100 \
    psutil==5.9.6 \
    dnspython==2.4.2 \
    pypcap==1.3.0 \
    netifaces==0.11.0 \
    cryptography==41.0.7 \
    pyOpenSSL==23.3.0

# Copy application files
COPY . .

# Set permissions for network tools
RUN setcap cap_net_raw,cap_net_admin=eip /usr/bin/tcpdump && \
    setcap cap_net_raw,cap_net_admin=eip /usr/bin/tshark

# Configure environment
ENV STREAMLIT_SERVER_PORT=8502 \
    STREAMLIT_SERVER_ADDRESS=0.0.0.0 \
    STREAMLIT_SERVER_HEADLESS=true \
    STREAMLIT_SERVER_FILE_WATCHER_TYPE=none \
    NETWATCH_ALLOW_ROOT=1

# Expose port
EXPOSE 8502

# Run the application with network capabilities
ENTRYPOINT ["python3", "-m", "streamlit", "run", "netwatch.py"]
CMD ["--server.address=0.0.0.0", "--server.port=8502"]
