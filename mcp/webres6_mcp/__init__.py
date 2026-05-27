# SPDX-FileCopyrightText: 2026 SAP SE and IPv6 Web Resource Checker contributors
#
# SPDX-License-Identifier: Apache-2.0

import argparse
import os

from .server import mcp
from . import tools
from . import resources
from . import prompts

__all__ = ["mcp"]


def main():
    parser = argparse.ArgumentParser(prog="webres6-mcp", description="webres6 MCP server")
    parser.add_argument(
        "--transport",
        choices=["stdio", "http"],
        default=None,
        help="Transport to use. Overrides WEBRES6_MCP_TRANSPORT. Default: stdio.",
    )
    args = parser.parse_args()

    transport = args.transport or os.environ.get("WEBRES6_MCP_TRANSPORT", "stdio")

    if transport == "http":
        mcp.run(transport="streamable-http")
    else:
        mcp.run(transport="stdio")
