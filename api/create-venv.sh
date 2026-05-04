#!/bin/bash
#
# SPDX-FileCopyrightText: 2026 SAP SE and IPv6 Web Resource Checker contributors
# SPDX-License-Identifier: Apache-2.0
#
DIR=$(cd $(dirname $(readlink -f "$0")) && pwd)

if [ ! -d "$DIR/.venv" ]; then
  echo "Creating virtual environment in $DIR/.venv"
  python3 -m venv "$DIR/.venv"
fi
(
  cd "$DIR"
  source ".venv/bin/activate"
  pip install --upgrade pip
  pip install -e .
  pip install -e ".[test]"
)
