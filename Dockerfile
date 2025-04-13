FROM python:3.9-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    tcpdump \
    tshark \
    curl \
    net-tools \
    iputils-ping \
    iproute2 \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY . .

# Set permissions for network tools
RUN chmod +x /usr/sbin/tcpdump
RUN setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump
RUN setcap cap_net_raw,cap_net_admin=eip /usr/bin/tshark

# Create necessary directories
RUN mkdir -p /app/captures /app/logs /app/reports

# Expose Streamlit port
EXPOSE 8501

# Configure Streamlit
ENV STREAMLIT_SERVER_PORT=8501
ENV STREAMLIT_SERVER_ADDRESS=0.0.0.0
ENV STREAMLIT_SERVER_HEADLESS=true
ENV STREAMLIT_SERVER_ENABLE_CORS=false

# Run the application
ENTRYPOINT ["streamlit", "run", "netwatch.py", \
    "--server.address=0.0.0.0", \
    "--server.port=8501", \
    "--browser.serverAddress=0.0.0.0", \
    "--server.enableCORS=false", \
    "--server.enableXsrfProtection=false"]
