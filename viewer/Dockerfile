# SPDX-FileCopyrightText: 2026 SAP SE and IPv6 Web Resource Checker contributors
#
# SPDX-License-Identifier: Apache-2.0
#
# Use official NGINX mainline image
FROM nginx:mainline

# Set default environment variables
ENV WEBRES6_API_URL=http://localhost:6400/
ENV DNSPROBE_API_URL=http://localhost:6453/
ENV NGINX_PORT=6480

# Copy viewer files
WORKDIR /usr/share/nginx/html
COPY viewer/viewer.* viewer/favicon.* ./
COPY viewer/fonts/ ./fonts/
COPY viewer/nginx.conf.template /etc/nginx/templates/default.conf.template
RUN mkdir -p .well-known/ res6/report