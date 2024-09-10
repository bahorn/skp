PAGE_SIZE = 4096


def pad_size(dlen, padding=PAGE_SIZE):
    extra = padding - (dlen % padding)
    return dlen + extra


def pad(data, padding=PAGE_SIZE, before=False, value=b'\x00'):
    extra = padding - (len(data) % padding)

    if before:
        return extra * value + data

    return data + extra * value
