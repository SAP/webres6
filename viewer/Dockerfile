# SPDX-FileCopyrightText: 2025 SAP SE and IPv6 Web Resource Checker contributors
#
# SPDX-License-Identifier: Apache-2.0
#
# Use official NGINX mainline image
FROM nginx:mainline

# Copy viewer files
WORKDIR /usr/share/nginx/html
COPY viewer/viewer.* viewer/favicon.* ./
COPY viewer/fonts/ ./fonts/
RUN ln -sf viewer.html index.html
RUN mkdir .well-known/
