#!/bin/sh
# SPDX-FileCopyrightText: 2026 SAP SE and IPv6 Web Resource Checker contributors
#
# SPDX-License-Identifier: Apache-2.0
#
# Injected via /docker-entrypoint.d/ — prepends load_module to nginx.conf
# so ngx_http_acme_module is available in the main context.
grep -q 'ngx_http_acme_module' /etc/nginx/nginx.conf || \
  sed -i '1s|^|load_module /usr/lib/nginx/modules/ngx_http_acme_module.so;\n|' /etc/nginx/nginx.conf
