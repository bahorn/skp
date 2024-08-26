#!/bin/bash
source .venv/bin/activate
pip install -r requirements.txt
cd ./tools/vmlinux-to-elf/ && python3 setup.py install
