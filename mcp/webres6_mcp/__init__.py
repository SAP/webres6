# SPDX-FileCopyrightText: 2026 SAP SE and IPv6 Web Resource Checker contributors
#
# SPDX-License-Identifier: Apache-2.0

from .server import mcp
from . import tools
from . import prompts

__all__ = ["mcp"]


def main():
    mcp.run(transport="stdio")
