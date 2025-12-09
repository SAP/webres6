# SPDX-FileCopyrightText: 2025 SAP SE and IPv6 Web Resource Checker contributors
#
# SPDX-License-Identifier: Apache-2.0
#
# Use official debian trixie based Python image as base
FROM python:3.14-slim-trixie
WORKDIR /app

# Install non-python dependencies
RUN apt update --yes \
  && apt upgrade --yes \
  && apt install --no-install-recommends --yes -o DPkg::options::="--force-overwrite" -o Dpkg::Options::="--force-confdef" \
                  bash curl \
  && apt clean \
  && rm -rf /var/lib/apt/lists/*

# Copy application code
COPY api/requirements.txt api/docker-entrypoint api/webres6-api.py api/webres6_storage.py api/webres6-api-metadata.xml ./

# Install python dependencies
RUN pip install --no-cache-dir -r requirements.txt; \
    pip install --no-cache-dir gunicorn[gthread]

# Don't copy viewer files into api image, viewer is served separately
# COPY viewer ./viewer/

# create empty extensions folder
RUN mkdir ./extensions

# get public suffix list
RUN curl -O https://publicsuffix.org/list/public_suffix_list.dat

# Start the app with Gunicorn
ENV GUNICORN_CMD_ARGS="--threads 32"
EXPOSE 6400
ENTRYPOINT [ "/app/docker-entrypoint" ]
