import sys
import os

# Add api_gateway and attack_simulator to the Python path for test imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), 'api_gateway')))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), 'attack_simulator')))
