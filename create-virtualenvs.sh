#!/bin/bash
#
# SPDX-FileCopyrightText: 2025 SAP SE and IPv6 Web Resource Checker contributors
# SPDX-License-Identifier: Apache-2.0
#
SCRIPT_DIR=$(cd $(dirname $(readlink -f "$0")) && pwd)

function create_venv() {
  DIR="$1"
  if [ ! -d "$DIR/.venv" ]; then
    echo "Creating virtual environment in $DIR/.venv"
    (
      cd "$DIR"
      source "create-venv.sh"
    )
  fi
}

# Register the shared hooks directory so git picks up pre-commit etc.
git -C "$SCRIPT_DIR" config core.hooksPath .githooks

# Create virtual environment if not existing
if [ ! -d "$SCRIPT_DIR/api/.venv" ]; then
  create_venv "$SCRIPT_DIR/api"
fi

# Create virtual environment if not existing
if [ ! -d "$SCRIPT_DIR/cli/.venv" ]; then
  create_venv "$SCRIPT_DIR/cli"
fi

# Create virtual environment if not existing
if [ ! -d "$SCRIPT_DIR/mcp/.venv" ]; then
  create_venv "$SCRIPT_DIR/mcp"
fi

# Ensure jquery is available in the viewer directory (needed to serve the viewer
# locally through the API in dev). Runs regardless of venv state; skips cleanly
# when npm is not installed, since the viewer is optional for API/CLI/MCP work.
VIEWER_DIR="$SCRIPT_DIR/viewer"
if [ -f "$VIEWER_DIR/jquery.min.js" ]; then
  echo "jquery.min.js already present — skipping viewer dependency install."
elif command -v npm >/dev/null 2>&1; then
  echo "Downloading jquery.min.js into the viewer directory..."
  ( cd "$VIEWER_DIR" && npm ci --omit=dev )
else
  echo "npm not found — skipping viewer jquery download. Install Node.js/npm and run 'cd viewer && npm ci' if you want to serve the viewer locally."
fi

