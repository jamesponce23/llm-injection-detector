#!/bin/bash
# Run the prompt-injection-detector test suite
cd "$(dirname "$0")"
.venv/bin/pytest tests/ "$@"
