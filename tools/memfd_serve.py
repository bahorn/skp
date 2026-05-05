"""
Serves a file via a memfd.

This allows it to exist as a temp file which will be automatically cleaned up
when all the users are done.
"""
import os
import sys
import time


def main():
    fd = os.memfd_create(sys.argv[1])
    with open(sys.argv[2], 'rb') as f:
        os.write(fd, f.read())

    time.sleep(5)


if __name__ == "__main__":
    main()
