#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if [[ -n "${VENV_PYTHON:-}" && -x "${VENV_PYTHON}" ]]; then
	PYTHON_BIN="${VENV_PYTHON}"
elif [[ -x "${SCRIPT_DIR}/.venv/bin/python" ]]; then
	PYTHON_BIN="${SCRIPT_DIR}/.venv/bin/python"
elif [[ -x "${SCRIPT_DIR}/../../.venv/bin/python" ]]; then
	PYTHON_BIN="${SCRIPT_DIR}/../../.venv/bin/python"
else
	PYTHON_BIN="$(command -v python3)"
fi

UVICORN_ARGS=(app.main:app --app-dir "$SCRIPT_DIR" --host 0.0.0.0 --port 8000)

if [[ "${RUN_RELOAD:-0}" == "1" ]]; then
	UVICORN_ARGS+=(--reload)
fi

"${PYTHON_BIN}" -m uvicorn "${UVICORN_ARGS[@]}"
