# SPDX-FileCopyrightText: 2026 SAP SE and IPv6 Web Resource Checker contributors
#
# SPDX-License-Identifier: Apache-2.0

FROM python:3.14-slim-trixie AS webres6-mcp

WORKDIR /app

# Install only the package metadata first to leverage Docker's layer cache
COPY mcp/pyproject.toml ./
COPY mcp/webres6_mcp ./webres6_mcp

RUN pip install --no-cache-dir --progress-bar off .

ENV WEBRES6_MCP_TRANSPORT=http \
    FASTMCP_HOST=::0 \
    FASTMCP_PORT=6470

EXPOSE 6470

CMD ["webres6-mcp"]
