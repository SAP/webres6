# SPDX-FileCopyrightText: 2026 SAP SE and IPv6 Web Resource Checker contributors
#
# SPDX-License-Identifier: Apache-2.0
#
# Use official NGINX mainline image
FROM nginx:mainline

# Copy viewer files
WORKDIR /usr/share/nginx/html
COPY viewer/viewer.* viewer/favicon.* ./
COPY viewer/fonts/ ./fonts/
COPY viewer/nginx.conf.template /etc/nginx/templates/default.conf.template
RUN mkdir -p .well-known/ res6/report