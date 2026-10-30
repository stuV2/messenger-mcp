#!/usr/bin/env bash
# Offline, create-only packaging wrapper. Never starts services or installs tools.
set -euo pipefail
HERE="$(cd -- "$(dirname -- "$0")" && pwd)"
# Optional explicit interpreter. Otherwise use an already installed Python 3.
PYTHON="${MESSENGER_PACKAGING_PYTHON:-python3}"
exec "$PYTHON" -I -B "$HERE/install_macos.py" "$@"
