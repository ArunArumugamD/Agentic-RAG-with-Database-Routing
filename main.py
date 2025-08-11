"""
Main entry point for the Agentic RAG with Database Routing system.
Quick launcher for development and testing.
"""

import sys
from pathlib import Path

# Add src to Python path
sys.path.insert(0, str(Path(__file__).parent))

from scripts.run_server import main

if __name__ == "__main__":
    main()