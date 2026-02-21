#!/usr/bin/env python3
"""Endevor-MCP Server Entry Point."""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from endevor_mcp.server import main

if __name__ == "__main__":
    main()
