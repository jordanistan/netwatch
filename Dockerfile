FROM python:3.9-slim

# Set working directory
WORKDIR /app

# Install dependencies
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
    && rm -rf /var/lib/apt/lists/*

# Create directories
RUN mkdir -p /app/captures /app/logs /app/reports

# Copy requirements and install
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY . .

# Set permissions for network tools
RUN setcap cap_net_raw,cap_net_admin=eip /usr/bin/tcpdump && \
    setcap cap_net_raw,cap_net_admin=eip /usr/bin/tshark

# Configure environment
ENV STREAMLIT_SERVER_PORT=8502 \
    STREAMLIT_SERVER_ADDRESS=0.0.0.0

# Expose port
EXPOSE 8502

# Run the application
CMD ["python3", "-m", "streamlit", "run", "netwatch.py", "--server.address=0.0.0.0", "--server.port=8502"]
