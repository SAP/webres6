# SPDX-FileCopyrightText: 2026 SAP SE and IPv6 Web Resource Checker contributors
#
# SPDX-License-Identifier: Apache-2.0
#
# ── Stage 1: build unbound with Python bindings ──────────────────────────────
FROM python:3.15.0a8-slim-trixie AS unbound-builder
WORKDIR /build

# Set MAX_TARGET_NX to 25 (upstream: 5) to work around CDN issues with many IPv4-only DNS servers
ARG MAX_TARGET_NX=25
ARG UNBOUND_IMAGE="https://nlnetlabs.nl/downloads/unbound/unbound-1.25.0.tar.gz"

RUN apt-get update -q \
  && apt upgrade -q --yes \
  && apt install -q --no-install-recommends --yes -o DPkg::options::="--force-overwrite" -o Dpkg::Options::="--force-confdef" \
      bash curl ca-certificates \
      pkg-config build-essential libssl-dev libexpat1-dev \
  && apt-get clean \
  && rm -rf /var/lib/apt/lists/*

# Install setup tools and swig for building Python bindings
RUN pip install --no-cache-dir setuptools swig

# Fetch and verify the latest unbound source
RUN curl -fsSL "$UNBOUND_IMAGE" \
      -o unbound.tar.gz \
  && tar xzf unbound.tar.gz \
  && mv unbound-* unbound

WORKDIR /build/unbound

# patch MAX_TARGET_NX to work around Akamai issues
RUN sed "s/#define MAX_TARGET_NX\s.*$/#define MAX_TARGET_NX\t\t${MAX_TARGET_NX}/" -i iterator/iterator.h && \
    grep -e "MAX_TARGET_NX\s\s*${MAX_TARGET_NX}" iterator/iterator.h

# Configure with Python module support; install into /usr/local so it is
# easy to copy into the final image without polluting system paths.
RUN ./configure \
      --prefix=/usr/local \
      --with-pyunbound \
      --with-ssl \
      --with-libexpat=/usr \
      PYTHON=/usr/local/bin/python3 \
  && make -j"$(nproc)" \
  && make install

# ── Stage 2: runtime image ────────────────────────────────────────────────────
# Use official debian trixie based Python image as base
FROM python:3.15.0a8-slim-trixie
WORKDIR /app

# Install non-python dependencies
RUN apt update -q --yes \
  && apt upgrade -q --yes \
  && apt install -q --no-install-recommends --yes -o DPkg::options::="--force-overwrite" -o Dpkg::Options::="--force-confdef" \
      bash curl ca-certificates \
      ldnsutils \
      libssl3 libexpat1 \
  && apt clean \
  && rm -rf /var/lib/apt/lists/*

# Copy unbound Python binding (_unbound.so + unbound.py) built in stage 1.
# Both stages share the same debian:trixie-slim base, so the Python version
# (and thus dist-packages path) is identical in builder and runtime.
COPY --from=unbound-builder /usr/local/lib/ /usr/local/lib/
RUN ldconfig

# Copy application code
COPY api/pyproject.toml api/docker-entrypoint api/webres6_api.py api/webres6_*.py api/webres6-api-metadata.xml api/unbound.v6only.conf ./

# Install python dependencies
RUN pip install --no-cache-dir . ; \
    pip install --no-cache-dir gunicorn[gthread]

# Don't copy viewer files into api image, viewer is served separately

# create empty server config folder
RUN mkdir ./serverconfig

# Load root hints for unbound
RUN curl -fsSL -o /app/named.cache https://www.internic.net/domain/named.cache

# get public suffix list
RUN curl -fsSL -O https://publicsuffix.org/list/public_suffix_list.dat

# Create non-root user and switch to it
RUN mkdir -p /app/run && \
    chown 999:999 /app/run && \
    groupadd -g 999 app && \
    useradd -u 999 -M -d /app/run -g app app
USER app

# Start the app with Gunicorn
ENV GUNICORN_CMD_ARGS="--threads 32"
EXPOSE 6400
ENTRYPOINT [ "/app/docker-entrypoint" ]
