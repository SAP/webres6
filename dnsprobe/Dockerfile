# SPDX-FileCopyrightText: 2025 SAP SE and IPv6 Web Resource Checker contributors
#
# SPDX-License-Identifier: Apache-2.0
#
# Use official alpine based Python image
FROM debian:trixie-slim
WORKDIR /app

# Install non-python dependencies
RUN  apt update --yes\
  && apt install --yes bash python3 python3-unbound python3-flask gunicorn python3-gunicorn\
  && apt clean \
  && rm -rf /var/lib/apt/lists/*

# Copy application code
COPY dnsprobe/docker-entrypoint dnsprobe/dnsprobe.py dnsprobe/unbound.v6only.conf ./

# Start the app with Gunicorn
ENV GUNICORN_CMD_ARGS="--threads 32"
EXPOSE 6400
ENTRYPOINT [ "/app/docker-entrypoint" ]
