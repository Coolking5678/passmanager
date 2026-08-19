"""
main.py
Entry point for the Vault Password Manager application.
"""

import sys
import os

# Ensure the project root is on the path regardless of where the script is called from
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from gui.app_ui import run_app

if __name__ == "__main__":
    run_app()
