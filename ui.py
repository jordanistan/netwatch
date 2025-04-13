import streamlit as st
import variables

def setup_sidebar():
    """Setup the sidebar with profile and navigation"""
    st.sidebar.title("NetWatch 🔍")
    
    # Only try to load profile picture if it exists
    if variables.DEFAULT_PROFILE.exists():
        st.sidebar.image(str(variables.DEFAULT_PROFILE))
    
    st.sidebar.markdown("---")
    
    # Add description
    st.sidebar.markdown("""
    ### About
    NetWatch is a network monitoring and analysis tool designed for educational purposes.
    
    ⚠️ **Note**: Some features require root/admin privileges.
    """)
    
    st.sidebar.markdown("---")
    
    # Navigation with descriptions
    action = st.sidebar.radio(
        "Select Action",
        options=["Network Scan", "Traffic Capture", "PCAP Analysis"],
        help="Choose a monitoring action to perform"
    )
    
    # Show relevant help text based on selection
    if action == "Network Scan":
        st.sidebar.info("📡 Scans your local network to discover active devices")
    elif action == "Traffic Capture":
        st.sidebar.info("📊 Captures and analyzes network traffic in real-time")
    else:
        st.sidebar.info("📂 Analyze previously captured PCAP files")
    
    return action
