import streamlit as st

def setup_sidebar():
    """Setup the sidebar with profile and navigation"""
    st.sidebar.title("NetWatch 🔍")
    
    # Add logo/icon as emoji
    st.sidebar.markdown("""
    <div style='text-align: center; margin-bottom: 1rem;'>
        <h1 style='font-size: 3rem;'>🌐</h1>
    </div>
    """, unsafe_allow_html=True)
    
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
