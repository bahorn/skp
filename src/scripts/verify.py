import sys
import argparse


def main():
    parser = argparse.ArgumentParser(prog='verify')
    parser.add_argument('logfile')
    parser.add_argument('--invert', action='store_true')

    args = parser.parse_args()

    # All good kernels should feature this.
    want = {
        'PATCHED KERNEL': 0,
        'Please press Enter to activate this console.': 0
    }
    # If we find these, bad patch
    dont_want = {'panic': 0, 'KASAN': 0, 'BUG': 0}

    for line in open(args.logfile, 'r'):
        line = line.strip()
        for key in want:
            if key in line:
                want[key] += 1
        for key in dont_want:
            if key in line:
                dont_want[key] += 1

    bad = False

    for key in want:
        if want[key] == 0:
            print(f'* Missing "{key}"')
            bad = True

    for key in dont_want:
        if dont_want[key] > 0:
            print(f'* Found "{key}"')
            bad = True

    if args.invert:
        bad = not bad

    sys.exit({True: 0, False: -1}[not bad])


if __name__ == "__main__":
    main()
