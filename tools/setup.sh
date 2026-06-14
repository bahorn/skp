#!/bin/bash
source .venv/bin/activate
pip install -r requirements.txt
# all the latest commits at the time of writing.
(git clone https://github.com/marin-m/vmlinux-to-elf tools/vmlinux-to-elf \
    && cd tools/vmlinux-to-elf \
    && git checkout 19683fb95b29cd31362d49e6f48ab8368f96cbdf)
(git clone https://github.com/bahorn/easylkb tools/easylkb \
    && cd tools/easylkb/ \
    && git checkout 803a700cf95f772717ac77828bf90e8e2c824caf)
(git clone https://github.com/bahorn/klude2 tools/klude2 \
    && cd tools/klude2/ \
    && git checkout 15b5aa8f692ad1dd89aecf59cc6cf896df0f8a98)
