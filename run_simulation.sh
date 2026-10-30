#!/bin/bash
source .venv/bin/activate 2>/dev/null
python simulator_main.py --scenario "${1:-mixed}"
