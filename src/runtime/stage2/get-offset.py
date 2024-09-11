import sys

target_str = b'initcall_runtime_thunk\x00'

offset = open(sys.argv[1], 'rb').read().find(target_str) + len(target_str)
print(f'UINT32 runtime_bin_offset = {offset};')
