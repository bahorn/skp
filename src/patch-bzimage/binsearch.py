import re


class SearchObject:
    def pattern(self):
        return self._data

    def size(self):
        return len(self._data)


class FixedBytes(SearchObject):
    def __init__(self, data):
        res = bytes(
            ''.join(map(lambda x: '\\x{0:0{1}X}'.format(x, 2), data)),
            'ascii'
        )

        self._data = res


class SkipBytes(SearchObject):
    def __init__(self, n_bytes=1):
        self._data = b'.' * n_bytes


class BinSearch:
    def __init__(self, patterns):
        pattern = BinSearch.generate_pattern(patterns)
        self._pattern = re.compile(
            pattern,
            flags=re.S + re.M
        )

    def search(self, data):
        res = []
        for match in self._pattern.finditer(data):
            res.append((match.start(), match.end(), match.group()))
        return res

    @staticmethod
    def generate_pattern(so):
        return b''.join(map(lambda x: x.pattern(), so))
