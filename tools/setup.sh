#!/bin/bash
source .venv/bin/activate
pip install -r requirements.txt
git clone https://github.com/marin-m/vmlinux-to-elf tools/vmlinux-to-elf
git clone https://github.com/deepseagirl/easylkb tools/easylkb
