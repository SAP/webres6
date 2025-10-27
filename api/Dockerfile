# SPDX-FileCopyrightText: 2025 SAP SE and IPv6 Web Resource Checker contributors
#
# SPDX-License-Identifier: Apache-2.0
#
# Use official alpine based Python image
FROM python:3.13-alpine
WORKDIR /app

# Install non-python dependencies
RUN apk add --no-cache bash

# Copy application code
COPY api/requirements.txt api/docker-entrypoint api/webres6-api.py api/webres6-api-metadata.xml ./

# Install python dependencies
RUN pip install --no-cache-dir -r requirements.txt; \
    pip install --no-cache-dir gunicorn[gthread]

# Copy viewer files - disabled in API image
# COPY viewer ./viewer/

# create empty extensions folder
RUN mkdir ./extensions

# Start the app with Gunicorn
ENV GUNICORN_CMD_ARGS="--threads 32"
EXPOSE 6400
ENTRYPOINT [ "/app/docker-entrypoint" ]
