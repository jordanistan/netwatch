#!/bin/bash
# Ensure script is run with sudo
if [ "$EUID" -ne 0 ]; then 
    echo "Please run with sudo"
    exit 1
fi

# Set PATH to include Python binaries
export PATH="/usr/local/bin:$PATH"

# Run Streamlit with the current user's environment
sudo -E -u $SUDO_USER streamlit run netwatch.py
