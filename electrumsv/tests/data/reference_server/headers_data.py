import struct

GENESIS_HEADER = \
    b'\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' \
    b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' \
    b';\xa3\xed\xfdz{\x12\xb2z\xc7,>gv\x8fa\x7f\xc8\x1b\xc3\x88\x8aQ2:\x9f\xb8' \
    b'\xaaK\x1e^J\xda\xe5IM\xff\xff\x7f \x02\x00\x00\x00'
raw_header = bytes.fromhex("010000000000000000000000000000000000000000000000000000000000000000000000"
                           "3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4adae5494d"
                           "ffff7f2002000000")
height_bin = struct.pack('<I', 0)
GENESIS_TIP_NOTIFICATION_BINARY = raw_header + height_bin
