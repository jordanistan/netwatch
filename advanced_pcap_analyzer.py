#!/usr/bin/env python3
"""Advanced PCAP Analysis for NetWatch

This standalone script provides advanced PCAP analysis features including:
- Website categorization (including adult site detection)
- File download identification with source and thumbnails
- Media extraction and replay (audio, video, images)
- SIP call extraction and replay
- Plaintext communications display
"""

import sys
import logging
from pathlib import Path
import streamlit as st
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

# Import NetWatch components
from network.content_analyzer import ContentAnalyzer
from ui.content_display import show_content_analysis

def setup_page():
    """Setup the main page configuration"""
    st.set_page_config(
        page_title="NetWatch Advanced PCAP Analysis",
        page_icon="🔍",
        layout="wide"
    )
    
    # Add home button in sidebar
    with st.sidebar:
        if st.button("🏠 Back to NetWatch"):
            st.stop()
            import subprocess
            subprocess.Popen(['streamlit', 'run', 'netwatch.py'])
    
    st.title("🔍 NetWatch Advanced PCAP Analysis")
    st.markdown("""
    This tool provides deep packet inspection and content extraction features:
    - Website categorization (including adult site detection)
    - File download identification with source information
    - Media extraction and replay (audio, video, images)
    - SIP call extraction and replay
    - Plaintext communications display
    """)

def analyze_pcap(pcap_file):
    """Analyze PCAP file for content extraction"""
    try:
        # Create content analyzer
        content_analyzer = ContentAnalyzer('reports')
        
        # Analyze PCAP file
        with st.spinner(f"Analyzing PCAP file: {pcap_file}"):
            results = content_analyzer.analyze_pcap(pcap_file)
            
        if results:
            st.success(f"✅ Analysis complete: {pcap_file}")
            return results
        else:
            st.error("❌ Analysis failed to produce results")
            return None
    except Exception as e:
        st.error(f"❌ Error analyzing PCAP file: {str(e)}")
        logging.exception("Error in analyze_pcap")
        return None

def main():
    """Main entry point"""
    setup_page()
    
    # File uploader for PCAP files
    uploaded_file = st.file_uploader("Upload a PCAP file", type=["pcap", "cap"])
    
    # Or select from existing captures
    captures_dir = Path("captures")
    if captures_dir.exists():
        pcap_files = list(captures_dir.glob("*.pcap"))
        if pcap_files:
            pcap_files.sort(key=lambda x: x.stat().st_mtime, reverse=True)
            selected_pcap = st.selectbox(
                "Or select an existing PCAP file",
                pcap_files,
                format_func=lambda x: f"{x.name} ({datetime.fromtimestamp(x.stat().st_mtime).strftime('%Y-%m-%d %H:%M:%S')})"
            )
            
            if st.button("Analyze Selected PCAP", type="primary"):
                results = analyze_pcap(selected_pcap)
                if results:
                    show_content_analysis(results)
    
    # Handle uploaded file
    if uploaded_file is not None:
        # Save uploaded file temporarily
        temp_file = Path("captures") / uploaded_file.name
        temp_file.parent.mkdir(exist_ok=True)
        
        with open(temp_file, "wb") as f:
            f.write(uploaded_file.getbuffer())
        
        # Analyze the uploaded file
        results = analyze_pcap(temp_file)
        if results:
            show_content_analysis(results)
    
    # Command line argument for PCAP file
    if len(sys.argv) > 1 and sys.argv[1] == '--pcap':
        if len(sys.argv) > 2:
            pcap_file = sys.argv[2]
            if Path(pcap_file).exists():
                results = analyze_pcap(pcap_file)
                if results:
                    show_content_analysis(results)
            else:
                st.error(f"❌ PCAP file not found: {pcap_file}")
        else:
            st.error("❌ Please provide a PCAP file path after --pcap")

if __name__ == "__main__":
    main()
