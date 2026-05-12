# SPDX-FileCopyrightText: 2026 SAP SE and IPv6 Web Resource Checker contributors
#
# SPDX-License-Identifier: Apache-2.0

import os

WEBRES6_API_URL   = os.environ.get("WEBRES6_API_URL",  "https://webres6.dev.sap").rstrip("/").rstrip("/res6") + "/res6"
DNSPROBE_URL      = os.environ.get("DNSPROBE_API_URL", "https://webres6.dev.sap").rstrip("/").rstrip("/dnsprobe") + "/dnsprobe"
