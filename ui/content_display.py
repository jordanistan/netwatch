"""UI components for displaying advanced content analysis results"""
import streamlit as st
import pandas as pd
from pathlib import Path
import base64
import mimetypes

def show_content_analysis(content_data):
    """Display advanced content analysis results
    
    Args:
        content_data: Dictionary with content analysis results
    """
    if not content_data:
        st.info("No content analysis data available")
        return
        
    # Create tabs for different content types
    websites_tab, downloads_tab, media_tab, plaintext_tab, calls_tab = st.tabs([
        "Websites", "Downloads", "Media", "Plaintext", "VoIP Calls"
    ])
    
    # Websites Tab (with adult site categorization)
    with websites_tab:
        st.subheader("Website Visits")
        
        if content_data.get('websites'):
            # Split into adult and regular websites
            adult_sites = [site for site in content_data['websites'] if site.get('is_adult')]
            regular_sites = [site for site in content_data['websites'] if not site.get('is_adult')]
            
            col1, col2 = st.columns(2)
            with col1:
                st.metric("Total Websites", len(content_data['websites']))
            with col2:
                st.metric("Adult Websites", len(adult_sites))
            
            # Show regular websites
            st.subheader("Regular Websites")
            if regular_sites:
                websites_df = pd.DataFrame(regular_sites)
                st.dataframe(websites_df, hide_index=True, use_container_width=True)
            else:
                st.info("No regular website visits detected")
            
            # Show adult websites with warning
            if adult_sites:
                st.subheader("⚠️ Adult Websites")
                with st.expander("Show Adult Websites (Click to Expand)", expanded=False):
                    websites_df = pd.DataFrame(adult_sites)
                    st.dataframe(websites_df, hide_index=True, use_container_width=True)
            
        else:
            st.info("No website visits detected")
    
    # Downloads Tab
    with downloads_tab:
        st.subheader("File Downloads")
        
        if content_data.get('file_downloads'):
            st.metric("Total Downloads", len(content_data['file_downloads']))
            
            for i, download in enumerate(content_data['file_downloads']):
                with st.expander(f"Download {i+1}: {Path(download['filename']).name}", expanded=False):
                    col1, col2 = st.columns([1, 3])
                    
                    with col1:
                        # Try to show thumbnail
                        try:
                            if Path(download['filename']).exists():
                                mime_type = download.get('type', 'application/octet-stream')
                                if 'pdf' in mime_type:
                                    st.image("https://cdn-icons-png.flaticon.com/512/337/337946.png", width=100)
                                elif 'word' in mime_type or 'doc' in mime_type:
                                    st.image("https://cdn-icons-png.flaticon.com/512/337/337932.png", width=100)
                                elif 'excel' in mime_type or 'sheet' in mime_type:
                                    st.image("https://cdn-icons-png.flaticon.com/512/337/337958.png", width=100)
                                else:
                                    st.image("https://cdn-icons-png.flaticon.com/512/2965/2965335.png", width=100)
                        except Exception:
                            st.image("https://cdn-icons-png.flaticon.com/512/2965/2965335.png", width=100)
                    
                    with col2:
                        st.write(f"**Source:** {download.get('source', 'Unknown')}")
                        st.write(f"**Type:** {download.get('type', 'Unknown')}")
                        st.write(f"**Size:** {download.get('size', 0)} bytes")
                        
                        # Download button
                        if Path(download['filename']).exists():
                            with open(download['filename'], "rb") as file:
                                st.download_button(
                                    label="Download File",
                                    data=file,
                                    file_name=Path(download['filename']).name,
                                    mime=download.get('type', 'application/octet-stream')
                                )
        else:
            st.info("No file downloads detected")
    
    # Media Tab
    with media_tab:
        st.subheader("Media Files")
        
        if content_data.get('media_files'):
            st.metric("Total Media Files", len(content_data['media_files']))
            
            # Group by media type
            images = [m for m in content_data['media_files'] if 'image' in m.get('type', '')]
            audio = [m for m in content_data['media_files'] if 'audio' in m.get('type', '')]
            video = [m for m in content_data['media_files'] if 'video' in m.get('type', '')]
            
            # Images
            if images:
                st.subheader("Images")
                columns = st.columns(3)
                for i, img in enumerate(images):
                    col = columns[i % 3]
                    with col:
                        try:
                            if Path(img['filename']).exists():
                                st.image(img['filename'], caption=Path(img['filename']).name, use_column_width=True)
                        except Exception:
                            st.error(f"Could not display image: {Path(img['filename']).name}")
            
            # Audio
            if audio:
                st.subheader("Audio")
                for i, audio_file in enumerate(audio):
                    try:
                        if Path(audio_file['filename']).exists():
                            with st.expander(f"Audio {i+1}: {Path(audio_file['filename']).name}", expanded=False):
                                st.audio(audio_file['filename'])
                    except Exception:
                        st.error(f"Could not play audio: {Path(audio_file['filename']).name}")
            
            # Video
            if video:
                st.subheader("Video")
                for i, video_file in enumerate(video):
                    try:
                        if Path(video_file['filename']).exists():
                            with st.expander(f"Video {i+1}: {Path(video_file['filename']).name}", expanded=False):
                                st.video(video_file['filename'])
                    except Exception:
                        st.error(f"Could not play video: {Path(video_file['filename']).name}")
        else:
            st.info("No media files detected")
    
    # Plaintext Tab
    with plaintext_tab:
        st.subheader("Plaintext Communications")
        
        if content_data.get('plaintext'):
            st.metric("Total Plaintext Communications", len(content_data['plaintext']))
            
            for i, text in enumerate(content_data['plaintext']):
                with st.expander(f"Text {i+1}: {text.get('size', 0)} bytes", expanded=False):
                    st.code(text.get('content', ''), language=None)
        else:
            st.info("No plaintext communications detected")
    
    # VoIP Calls Tab
    with calls_tab:
        st.subheader("VoIP Calls")
        
        if content_data.get('sip_calls'):
            st.metric("Total Calls", len(content_data['sip_calls']))
            
            for i, call in enumerate(content_data['sip_calls']):
                with st.expander(f"Call {i+1}: {call.get('from', 'Unknown')} → {call.get('to', 'Unknown')}", expanded=False):
                    st.write(f"**From:** {call.get('from', 'Unknown')}")
                    st.write(f"**To:** {call.get('to', 'Unknown')}")
                    st.write(f"**Call ID:** {call.get('call_id', 'Unknown')}")
                    
                    # Play audio if available
                    if call.get('audio_file') and Path(call['audio_file']).exists():
                        st.audio(call['audio_file'])
                    else:
                        st.info("No audio recording available for this call")
        else:
            st.info("No VoIP calls detected")

def get_file_data_url(file_path, mime_type=None):
    """Generate a data URL for a file"""
    try:
        if not mime_type:
            mime_type, _ = mimetypes.guess_type(file_path)
            if not mime_type:
                mime_type = 'application/octet-stream'
                
        with open(file_path, "rb") as file:
            data = file.read()
            encoded = base64.b64encode(data).decode()
            return f"data:{mime_type};base64,{encoded}"
    except Exception:
        return None
