#!/bin/bash
source .venv/bin/activate
pip install -r requirements.txt
git clone https://github.com/marin-m/vmlinux-to-elf tools/vmlinux-to-elf
git clone https://github.com/deepseagirl/easylkb tools/easylkb
git clone https://github.com/bahorn/klude2 tools/klude2
