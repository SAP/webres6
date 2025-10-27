#!/bin/bash
#
# This is a wrapper script to start run webres6-client.py
# it uses WEBRES6_API_URL as API backend if set,
# otherwise it starts a local webres6-server.py instance.
#
# SPDX-FileCopyrightText: 2025 SAP SE and IPv6 Web Resource Checker contributors
# SPDX-License-Identifier: Apache-2.0
#
SCRIPT_DIR=$(cd $(dirname $(readlink -f "$0")) && pwd)

function create_venv() {
  DIR="$1"
  if [ ! -d "$DIR/.venv" ]; then
    echo "Creating virtual environment in $DIR/.venv"
    python3 -m venv "$DIR/.venv"
  fi
  (
    cd "$DIR"
    source ".venv/bin/activate"
    pip install --upgrade pip
    pip install -r "requirements.txt"  
  )
}

# Create virtual environment if not existing
if [ ! -d "$SCRIPT_DIR/api/.venv" ]; then
  create_venv "$SCRIPT_DIR/api"
fi

# Create virtual environment if not existing
if [ ! -d "$SCRIPT_DIR/cli/.venv" ]; then
  create_venv "$SCRIPT_DIR/cli"
fi
