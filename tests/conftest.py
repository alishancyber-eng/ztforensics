"""
Pytest configuration: add api_gateway directory to the Python path
so tests can import modules directly.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api_gateway"))
