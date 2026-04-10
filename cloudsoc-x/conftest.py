"""
Shared pytest fixtures for CloudSOC-X.
"""
import sys
import os

# Make src/ importable from tests/
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "api"))
