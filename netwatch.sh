#!/bin/bash

# --------------------------
# Configuration Variables
# --------------------------
CONFIG_FILE="$PWD/netwatch.conf"
PCAP_DIR="$PWD/captures"
LOG_FILE="$PWD/logs/presence.log"
ALERT_LOG="$PWD/logs/alerts.log"
THRESHOLD_BYTES=1000000  # 1MB threshold for traffic alerts
NETWORK_RANGE="192.168.1.0/24"  # Adjust this to your network

# Create necessary directories
mkdir -p "$(dirname "$LOG_FILE")" "$(dirname "$ALERT_LOG")"

# --------------------------
# Load Email/Slack from Config
# --------------------------

if [ -f "$CONFIG_FILE" ]; then
  source "$CONFIG_FILE"
else
  read -rp "Enter email for alerts: " ALERT_EMAIL
  read -rp "Enter Slack webhook URL (or leave blank to skip): " SLACK_WEBHOOK
  echo "ALERT_EMAIL=\"$ALERT_EMAIL\"" > "$CONFIG_FILE"
  echo "SLACK_WEBHOOK=\"$SLACK_WEBHOOK\"" >> "$CONFIG_FILE"
fi

# --------------------------
# Network Scan
# --------------------------

INTERFACE=$(ip route get 8.8.8.8 | awk '{print $5; exit}')
mapfile -t devices < <(sudo arp-scan --interface="$INTERFACE" "$NETWORK_RANGE" | grep -Eo '192\.168\.[0-9]+\.[0-9]+' | sort -u)

if [[ ${#devices[@]} -eq 0 ]]; then
  whiptail --msgbox "No devices found on the network." 10 40
  exit 1
fi

DEVICE_LIST=$(printf "%s\n" "${devices[@]}")
TARGET_IP=$(whiptail --title "Select Device" --menu "Choose a device to monitor" 20 60 10 $(for ip in "${devices[@]}"; do echo "$ip [ONLINE]"; done) 3>&1 1>&2 2>&3)
[ $? -ne 0 ] && exit 1

# --------------------------
# Monitoring Options
# --------------------------

ACTION=$(whiptail --title "Monitoring Options" --menu "Choose an action" 18 60 7 \
  "1" "Start Traffic Capture" \
  "2" "Run Background Logger" \
  "3" "Both (Capture + Logger)" \
  "4" "Analyze PCAP File" \
  "5" "Generate Reports Dashboard" \
  "6" "Exit" 3>&1 1>&2 2>&3)

# --------------------------
# Configuration
# --------------------------
REPORT_DIR="$PWD/reports"
DASHBOARD_DIR="$PWD/dashboard"

# Create necessary directories
mkdir -p "$PCAP_DIR" "$REPORT_DIR" "$DASHBOARD_DIR"

# --------------------------
# Functions
# --------------------------

function start_capture() {
  TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
  OUT="$PCAP_DIR/traffic_${TARGET_IP//./_}_$TIMESTAMP.pcap"
  echo "📡 Capturing to $OUT"
  sudo tcpdump -i "$INTERFACE" host "$TARGET_IP" and not port 53 and not port 123 and not port 137 and not port 138 -w "$OUT" &
  CAP_PID=$!

  MONITOR_BYTES=0
  sleep 30
  BYTES_NOW=$(sudo tcpdump -r "$OUT" -nn -tttt | wc -c)

  if [[ $BYTES_NOW -gt $THRESHOLD_BYTES ]]; then
    echo "$(date) - HIGH TRAFFIC DETECTED: $BYTES_NOW bytes from $TARGET_IP" >> "$ALERT_LOG"

    # Email Alert
    echo "High traffic alert for $TARGET_IP with $BYTES_NOW bytes" | mail -s "NetWatch Alert: High Traffic" "$ALERT_EMAIL"

    # Slack Alert
    if [[ -n "$SLACK_WEBHOOK" ]]; then
      curl -s -X POST -H 'Content-type: application/json' \
        --data "{\"text\":\"🚨 *High Traffic Alert*\nIP: $TARGET_IP\nBytes: $BYTES_NOW\nTime: $(date)\"}" \
        "$SLACK_WEBHOOK"
    fi
  fi

  wait "$CAP_PID"
}

function start_logger() {
  echo "📘 Logging device presence to $LOG_FILE (Ctrl+C to stop)"
  while true; do
    if ping -c 1 -W 1 "$TARGET_IP" &>/dev/null; then
      echo "$(date) - $TARGET_IP ONLINE" >> "$LOG_FILE"
    else
      echo "$(date) - $TARGET_IP OFFLINE" >> "$LOG_FILE"
    fi
    sleep 30
  done
}

function analyze_pcap() {
  # Select PCAP file
  PCAP_FILES=("$PCAP_DIR"/*.pcap)
  if [ ${#PCAP_FILES[@]} -eq 0 ]; then
    whiptail --msgbox "No PCAP files found in $PCAP_DIR" 10 40
    return 1
  fi

  # Build menu options for PCAP files
  MENU_OPTIONS=()
  for i in "${!PCAP_FILES[@]}"; do
    MENU_OPTIONS+=("$i" "$(basename "${PCAP_FILES[$i]}")") 
  done

  FILE_INDEX=$(whiptail --title "Select PCAP File" --menu "Choose a file to analyze" 20 60 10 "${MENU_OPTIONS[@]}" 3>&1 1>&2 2>&3)
  [ $? -ne 0 ] && return 1

  PCAP_FILE="${PCAP_FILES[$FILE_INDEX]}"
  TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
  BASE_NAME=$(basename "$PCAP_FILE" .pcap)
  
  echo "🔍 Analyzing $PCAP_FILE..."

  # Create report directory
  REPORT_PATH="$REPORT_DIR/${BASE_NAME}_${TIMESTAMP}"
  mkdir -p "$REPORT_PATH"

  # Generate JSON report
  echo "📊 Generating JSON report..."
  {
    echo "{"
    echo "  \"timestamp\": \"$(date -u +"%Y-%m-%dT%H:%M:%SZ")\","
    echo "  \"file_info\": {"
    echo "    \"name\": \"$BASE_NAME\","
    echo "    \"size\": $(stat -f%z "$PCAP_FILE")"
    echo "  },"
    echo "  \"http_traffic\": ["
    tshark -r "$PCAP_FILE" -Y "http" -T json 2>/dev/null | jq -c '.[]' | sed '$!s/$/,/'
    echo "  ],"
    echo "  \"media_streams\": ["
    tshark -r "$PCAP_FILE" -Y "rtp" -T json 2>/dev/null | jq -c '.[]' | sed '$!s/$/,/'
    echo "  ],"
    echo "  \"file_transfers\": ["
    tshark -r "$PCAP_FILE" -Y "http.request.method==\"POST\" || ftp-data" -T json 2>/dev/null | jq -c '.[]' | sed '$!s/$/,/'
    echo "  ]"
    echo "}"
  } > "$REPORT_PATH/analysis.json"

  # Generate CSV report
  echo "📊 Generating CSV report..."
  {
    echo "timestamp,protocol,source,destination,length,info"
    tshark -r "$PCAP_FILE" -T fields -e frame.time_epoch -e frame.protocols -e ip.src -e ip.dst -e frame.len -e frame.info -E header=n -E separator=, -E quote=d
  } > "$REPORT_PATH/analysis.csv"

  # Generate HTML report
  echo "📊 Generating HTML report..."
  cat > "$REPORT_PATH/analysis.html" << EOL
<!DOCTYPE html>
<html>
<head>
  <title>NetWatch Analysis Report - $BASE_NAME</title>
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
  <style>
    body { font-family: Arial, sans-serif; margin: 20px; }
    .chart-container { width: 800px; margin: 20px auto; }
  </style>
</head>
<body>
  <h1>NetWatch Analysis Report - $BASE_NAME</h1>
  <div class="chart-container">
    <canvas id="trafficChart"></canvas>
  </div>
  <div class="chart-container">
    <canvas id="protocolChart"></canvas>
  </div>
  <script>
    fetch('analysis.json')
      .then(response => response.json())
      .then(data => {
        // Traffic over time chart
        const trafficCtx = document.getElementById('trafficChart');
        new Chart(trafficCtx, {
          type: 'line',
          data: {
            labels: data.http_traffic.map(p => new Date(p.timestamp * 1000).toLocaleTimeString()),
            datasets: [{
              label: 'Traffic Volume',
              data: data.http_traffic.map(p => p.length)
            }]
          }
        });

        // Protocol distribution chart
        const protocolCtx = document.getElementById('protocolChart');
        new Chart(protocolCtx, {
          type: 'pie',
          data: {
            labels: ['HTTP', 'Media Streams', 'File Transfers'],
            datasets: [{
              data: [
                data.http_traffic.length,
                data.media_streams.length,
                data.file_transfers.length
              ]
            }]
          }
        });
      });
  </script>
</body>
</html>
EOL

  echo "✅ Analysis complete! Reports saved to: $REPORT_PATH"
  echo "📊 Opening HTML report..."
  open "$REPORT_PATH/analysis.html"
}

function generate_dashboard() {
  # Create dashboard index
  echo "🔄 Generating dashboard..."
  
  cat > "$DASHBOARD_DIR/index.html" << EOL
<!DOCTYPE html>
<html>
<head>
  <title>NetWatch Dashboard</title>
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
  <style>
    body { font-family: Arial, sans-serif; margin: 20px; }
    .grid { display: grid; grid-template-columns: repeat(2, 1fr); gap: 20px; }
    .card { border: 1px solid #ccc; padding: 15px; border-radius: 8px; }
    .chart-container { width: 100%; height: 300px; }
  </style>
</head>
<body>
  <h1>NetWatch Dashboard</h1>
  <div class="grid">
    <div class="card">
      <h2>Recent Captures</h2>
      <div id="capturesList"></div>
    </div>
    <div class="card">
      <h2>Traffic Overview</h2>
      <div class="chart-container">
        <canvas id="trafficOverview"></canvas>
      </div>
    </div>
  </div>
  <script>
    // Load and display recent captures
    fetch('captures.json')
      .then(response => response.json())
      .then(data => {
        const list = document.getElementById('capturesList');
        data.captures.forEach(capture => {
          const link = document.createElement('a');
          link.href = capture.report_path;
          link.textContent = capture.name;
          list.appendChild(link);
          list.appendChild(document.createElement('br'));
        });
      });

    // Update captures list
    function updateCapturesList() {
      const captures = [];
      const reports = document.querySelectorAll('#capturesList a');
      reports.forEach(report => {
        captures.push({
          name: report.textContent,
          report_path: report.href
        });
      });
      return { captures };
    }
  </script>
</body>
</html>
EOL

  # Create initial captures.json if it doesn't exist
  if [ ! -f "$DASHBOARD_DIR/captures.json" ]; then
    echo '{"captures": []}' > "$DASHBOARD_DIR/captures.json"
  fi

  echo "✅ Dashboard generated! Opening in browser..."
  open "$DASHBOARD_DIR/index.html"
}

# --------------------------
# Run Selected Option
# --------------------------

case "$ACTION" in
  1) start_capture ;;
  2) start_logger ;;
  3)
    start_logger &
    start_capture
    ;;
  4) analyze_pcap ;;
  5) generate_dashboard ;;
  *) echo "Goodbye!" && exit 0 ;;
esac