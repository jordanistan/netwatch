import streamlit as st
import variables
from netwatch import NetWatch, main

if __name__ == "__main__":
    # Configure the Streamlit page
    st.set_page_config(
        page_title=variables.APP_CONFIG["title"],
        page_icon=variables.APP_CONFIG["icon"],
        layout=variables.APP_CONFIG["layout"],
        initial_sidebar_state="expanded"
    )

    # Apply custom CSS
    st.markdown(variables.CUSTOM_CSS, unsafe_allow_html=True)
    
    # Run the main application
    main()
