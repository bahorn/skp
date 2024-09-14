import sys


def main():
    # All good kernels should feature this.
    want = {
        'PATCHED KERNEL': 0,
        'Please press Enter to activate this console.': 0
    }
    # If we find these, bad patch
    dont_want = {'panic': 0, 'KASAN': 0, 'BUG': 0}

    for line in open(sys.argv[1], 'r'):
        line = line.strip()
        for key in want:
            if key in line:
                want[key] += 1
        for key in dont_want:
            if key in line:
                dont_want[key] += 1

    bad = 0

    for key in want:
        if want[key] == 0:
            print(f'* Missing "{key}"')
            bad = -1

    for key in dont_want:
        if dont_want[key] > 0:
            print(f'* Found "{key}"')
            bad = -1

    sys.exit(bad)


if __name__ == "__main__":
    main()
