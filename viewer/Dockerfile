# SPDX-FileCopyrightText: 2026 SAP SE and IPv6 Web Resource Checker contributors
#
# SPDX-License-Identifier: Apache-2.0
#
# Use official NGINX mainline image
FROM nginx:1.31.0

# Set default environment variables
ENV WEBRES6_API_URL=http://disabled
ENV DNSPROBE_API_URL=http://disabled
ENV WEBRES6_MCP_URL=http://disabled
ENV NGINX_PORT=6480

# Copy viewer files
WORKDIR /usr/share/nginx/html
COPY viewer/viewer.* viewer/favicon.* viewer/404.html viewer/50x.html viewer/disabled.html ./
COPY viewer/fonts/ ./fonts/
COPY viewer/nginx.conf.template /etc/nginx/templates/default.conf.template
RUN mkdir -p .well-known/acme-challenge res6/report