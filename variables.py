from pathlib import Path

# Base paths
BASE_DIR = Path(__file__).parent
ASSETS_DIR = BASE_DIR / "assets"

# Ensure assets directory exists
ASSETS_DIR.mkdir(exist_ok=True)

# Default profile picture path - relative to assets directory
DEFAULT_PROFILE = ASSETS_DIR / "default_profile.png"
