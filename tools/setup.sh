#!/bin/bash
source .venv/bin/activate
pip install -r requirements.txt
# all the latest commits at the time of writing.
(git clone https://github.com/marin-m/vmlinux-to-elf tools/vmlinux-to-elf \
    && cd tools/vmlinux-to-elf \
    && git checkout 32afe399b0830b62a654d5c23bbae8c337daabd3)
(git clone https://github.com/bahorn/easylkb tools/easylkb \
    && cd tools/easylkb/ \
    && git checkout 803a700cf95f772717ac77828bf90e8e2c824caf)
(git clone https://github.com/bahorn/klude2 tools/klude2 \
    && cd tools/klude2/ \
    && git checkout 02a312531bc78c66c946fbfa2be051452c615bb2)
