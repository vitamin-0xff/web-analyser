import os
import sys
import pytest

# Ensure project root is on sys.path for imports like `core.*`
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

# Configure pytest-asyncio
pytest_plugins = ('pytest_asyncio',)