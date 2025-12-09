# SPDX-FileCopyrightText: 2025 SAP SE and IPv6 Web Resource Checker contributors
#
# SPDX-License-Identifier: Apache-2.0
#
# Use official debian trixie image as base
FROM debian:trixie-slim
WORKDIR /app

# Install dependencies for dnsprobe – we take debian python3 to get python3-unbound without building it ourselves
RUN  apt update --yes\
  && apt upgrade --yes \
  && apt install --no-install-recommends --yes -o DPkg::options::="--force-overwrite" -o Dpkg::Options::="--force-confdef" \
                  bash python3 python3-unbound python3-flask gunicorn python3-gunicorn \
  && apt clean \
  && rm -rf /var/lib/apt/lists/*

# Copy application code
COPY dnsprobe/docker-entrypoint dnsprobe/dnsprobe.py dnsprobe/unbound.v6only.conf ./

# Start the app with Gunicorn
ENV GUNICORN_CMD_ARGS="--threads 32"
EXPOSE 6453
ENTRYPOINT [ "/app/docker-entrypoint" ]