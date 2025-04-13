FROM python:3.9-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    tcpdump \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY . .

# Set permissions for tcpdump
RUN chmod +x /usr/sbin/tcpdump
RUN setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump

# Expose Streamlit port
EXPOSE 8501

# Run the application
ENTRYPOINT ["streamlit", "run", "netwatch.py", "--server.address=0.0.0.0"]
