import streamlit as st
import variables

def setup_sidebar():
    """Setup the sidebar with profile and navigation"""
    st.sidebar.title("NetWatch")
    
    # Only try to load profile picture if it exists
    if variables.DEFAULT_PROFILE.exists():
        st.sidebar.image(str(variables.DEFAULT_PROFILE))
    
    st.sidebar.markdown("---")
    return st.sidebar.radio(
        "Select Action",
        ["Network Scan", "Traffic Capture", "PCAP Analysis"]
    )
