#!/bin/bash
source .venv/bin/activate
pip install -r requirements.txt
git clone https://github.com/marin-m/vmlinux-to-elf tools/vmlinux-to-elf
