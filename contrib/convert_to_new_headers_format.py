"""
Use this script as follows:

> py .\convert_to_new_headers_format.py path\tp\headers2_paytomany
Successfully converted the old headers file ..\electrumsv\tests\data\headers\headers2_paytomany
to the new headers format in ..\electrumsv\tests\data\headers\headers3_paytomany

Note that the output file has changed "headers2" to "headers3"
"""

import os
import struct
import sys
from struct import Struct

import bitcoinx
from bitcoinx import Headers, double_sha256, hash_to_hex_str

assert bitcoinx._version[1] >= 8  # version >= 0.8

# The old bitcoinx (<=0.7.1) files are stored as a reserved area,
# followed by the headers consecutively.
# The reserved area has the following format:
#    a) reserved area size (little endian uint16)
#    b) version number (little endian uint16)
#    c) block header count (little endian uint32)
old_headers_struct_reserved = Struct('<HHI')


def main(old_headers, new_headers):
    # Check if the input file exists
    if not os.path.isfile(old_headers):
        print(f"Error: The file {old_headers} does not exist.")
        return

    # Read the contents of the input file
    with open(old_headers, 'rb') as hf:
        reserved_bytes = hf.read(old_headers_struct_reserved.size)
        try:
            actual_reserved_size, header_store_version, header_store_count = \
                old_headers_struct_reserved.unpack(reserved_bytes)
            assert header_store_version == 0
            raw_headers = hf.read(header_store_count * 80)
            assert len(raw_headers) % 80 == 0

            # chunk_size = 80
            # hashes = []
            # for i in range(0, len(raw_headers), chunk_size):
            #     chunk = raw_headers[i:i + chunk_size]
            #     hashes.append(hash_to_hex_str(double_sha256(chunk)))

        except (AssertionError, struct.error) as e:
            sys.exit(f"{e} - This headers file is corrupted")

    # Write the content to the output file
    with open(new_headers, 'wb') as hf:
        hf.write(raw_headers)
    print(f"Successfully converted the old headers file {old_headers} to the new headers format "
          f"in {new_headers}")

    # # Write the content to the output file
    # with open(new_headers+"_blockhashes", 'w') as hf:
    #     hf.writelines(hashes)


if __name__ == "__main__":
    # Check if the number of arguments is correct
    arg_count = len(sys.argv)
    if arg_count not in [2, 3]:
        print("Usage: python script.py old_headers [new_headers]")
        sys.exit(1)

    # Extract command line arguments
    old_headers = sys.argv[1]
    if arg_count == 3:
        new_headers = sys.argv[2]
    else:
        new_headers = old_headers.replace("headers2", "headers3")

    # Execute main function
    main(old_headers, new_headers)
