# SPDX-FileCopyrightText: 2026 SAP SE and IPv6 Web Resource Checker contributors
#
# SPDX-License-Identifier: Apache-2.0

FROM python:3.14-slim-trixie AS webres6-mcp

WORKDIR /app

# Install only the package metadata first to leverage Docker's layer cache
COPY mcp/pyproject.toml ./
COPY mcp/webres6_mcp ./webres6_mcp

RUN pip install --no-cache-dir --progress-bar off .

# Create non-root user and switch to it
RUN mkdir -p /app/run && \
    chown 999:999 /app/run && \
    groupadd -g 999 app && \
    useradd -u 999 -M -d /app/run -g app app
USER app

# default environment variables for MCP, can be overridden at runtime
ENV WEBRES6_MCP_TRANSPORT="http"
ENV FASTMCP_HOST="::0"
ENV FASTMCP_PORT=6470

EXPOSE 6470

CMD ["webres6-mcp"]
