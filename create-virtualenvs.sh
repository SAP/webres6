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
if [ ! -d "$SCRIPT_DIR/dnsprobe/.venv" ]; then
  create_venv "$SCRIPT_DIR/cli"
fi

# Create virtual environment if not existing
if [ ! -d "$SCRIPT_DIR/cli/.venv" ]; then
  create_venv "$SCRIPT_DIR/cli"
fi
