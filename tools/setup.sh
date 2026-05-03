#!/bin/bash
source .venv/bin/activate
pip install -r requirements.txt
# all the latest commits at the time of writing.
(git clone https://github.com/marin-m/vmlinux-to-elf tools/vmlinux-to-elf \
    && cd tools/vmlinux-to-elf \
    && git checkout 8dc277f28c62d2db10fbe36bb539ff973f045443)
(git clone https://github.com/bahorn/easylkb tools/easylkb \
    && cd tools/easylkb/ \
    && git checkout 803a700cf95f772717ac77828bf90e8e2c824caf)
(git clone https://github.com/bahorn/klude2 tools/klude2 \
    && cd tools/klude2/ \
    && git checkout fc0cbfb42d7f911cba4171516722abaf0f43cc19)
