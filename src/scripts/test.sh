#!/bin/bash
TIMEOUT=$1
TYPE=$2
# didn't work for some reason if I did it directly, but this works.
cat << EOF | timeout $TIMEOUT bash
just extra_qemu="" run-$TYPE > /tmp/log.txt
EOF

# Need to checkout the log for several messages
python3 ./src/scripts/verify.py /tmp/log.txt
