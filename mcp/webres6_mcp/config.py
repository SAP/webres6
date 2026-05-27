# SPDX-FileCopyrightText: 2026 SAP SE and IPv6 Web Resource Checker contributors
#
# SPDX-License-Identifier: Apache-2.0

import os

WEBRES6_API_URL = os.environ.get("WEBRES6_API_URL", "https://webres6.dev.sap").rstrip("/").removesuffix("/res6") + "/res6"
DNSPROBE_URL    = os.environ.get("DNSPROBE_API_URL", "https://webres6.dev.sap").rstrip("/").removesuffix("/dnsprobe")

# Browsable viewer URL. Derived from WEBRES6_API_URL (strip /res6) unless overridden.
# The viewer addresses individual reports via the URL fragment "#report:<id>".
WEBRES6_VIEWER_URL = os.environ.get("WEBRES6_VIEWER_URL", WEBRES6_API_URL.removesuffix("/res6")).rstrip("/")
