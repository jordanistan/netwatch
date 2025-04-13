from pathlib import Path

# Base paths
BASE_DIR = Path(__file__).parent
ASSETS_DIR = BASE_DIR / "assets"
CAPTURES_DIR = BASE_DIR / "captures"

# Ensure directories exist
ASSETS_DIR.mkdir(exist_ok=True)
CAPTURES_DIR.mkdir(exist_ok=True)

# App configuration
APP_CONFIG = {
    "title": "NetWatch Dashboard",
    "icon": "🌐",  # Network globe icon
    "layout": "wide"
}

# Theme colors
COLORS = {
    "background": "#0c0c0c",
    "surface": "#1a1a1a",
    "primary": "#ff00ff",  # Neon pink
    "secondary": "#0ff",   # Neon cyan
    "accent": "#ff3864",   # Hot pink
    "text": "#ffffff",
    "text_secondary": "#b3b3b3"
}

# Custom CSS for the Streamlit UI
CUSTOM_CSS = f"""
<style>
    /* Main theme */
    body {{{{ background-color: {COLORS['background']}; }}}}
    .main {{{{ 
        background-color: {COLORS['surface']};
        border-radius: 10px;
        padding: 2rem;
    }}}}
    
    /* Typography */
    h1, h2, h3 {{{{ color: {COLORS['primary']}; }}}}
    p {{{{ color: {COLORS['text']}; }}}}
    
    /* Buttons */
    .stButton>button {{{{
        background-color: {COLORS['secondary']};
        color: {COLORS['background']};
        border-radius: 5px;
        border: none;
        padding: 0.5rem 1rem;
        font-weight: bold;
        transition: all 0.3s ease;
    }}}}
    .stButton>button:hover {{{{
        background-color: {COLORS['primary']};
        box-shadow: 0 0 15px {COLORS['primary']};
    }}}}
    
    /* Inputs */
    .stTextInput>div>div>input {{{{
        background-color: {COLORS['surface']};
        color: {COLORS['secondary']};
        border: 1px solid {COLORS['secondary']};
        border-radius: 5px;
    }}}}
    
    /* Metrics */
    .stMetric {{{{
        background-color: {COLORS['surface']};
        border: 1px solid {COLORS['secondary']};
        border-radius: 10px;
        padding: 1rem;
    }}}}
    .stMetric:hover {{{{
        box-shadow: 0 0 15px {COLORS['secondary']};
    }}}}
    
    /* Charts */
    .js-plotly-plot {{{{
        background-color: {COLORS['surface']};
        border: 1px solid {COLORS['secondary']};
        border-radius: 10px;
        padding: 1rem;
    }}}}
    
    /* Sidebar */
    .css-1d391kg {{{{
        background-color: {COLORS['surface']};
    }}}}
    
    /* Progress bars */
    .stProgress > div > div > div > div {{{{
        background-color: {COLORS['primary']};
    }}}}
</style>
"""

# Footer content
FOOTER = """
<div style="text-align: center; margin-top: 2rem; padding: 1rem;">
    <p>© 2025 NetWatch - Monitoring with style! 🌐✨</p>
</div>
"""
