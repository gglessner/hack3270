#!/usr/bin/env python3
"""Endevor-MCP Server Entry Point (for use within hack3270-ai project)."""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from endevor_mcp.server import main

if __name__ == "__main__":
    main()
