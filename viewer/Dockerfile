# SPDX-FileCopyrightText: 2026 SAP SE and IPv6 Web Resource Checker contributors
#
# SPDX-License-Identifier: Apache-2.0
#
# Use official NGINX mainline image
FROM nginx:1.31.5

# Set default environment variables
ENV WEBRES6_API_URL=http://disabled
ENV DNSPROBE_API_URL=http://disabled
ENV WEBRES6_MCP_URL=http://disabled
# CSP connect-src source allowing direct report loading from S3/CDN. Scope it to
# the bucket path with a trailing "/" (prefix match) so only our bucket — not the
# whole shared S3 endpoint — is a valid fetch target. Empty = same-origin only
# (local/valkey/private delivery), e.g. "https://s3.eu-central-1.amazonaws.com/mybucket/".
ENV WEBRES6_ARCHIVE_SRC=""
ENV NGINX_PORT=6480

# Copy viewer files
WORKDIR /usr/share/nginx/html
COPY viewer/viewer.* viewer/favicon.* viewer/404.html viewer/50x.html viewer/disabled.html ./
COPY viewer/fonts/ ./fonts/
COPY viewer/nginx.conf.template /etc/nginx/templates/default.conf.template
RUN mkdir -p .well-known/acme-challenge res6/report && \
    ln -s ./.well-known/site.css ./site.css