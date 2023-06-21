#!/usr/bin/python

# This script will add the newly-decompressed clade section back into the modem binary
# This can be done manually in IDA or Ghidra but this makes it easier to distribute and load into BinDiff
# TODO: Have this map TLB sections as well

import os
import lief

def to_seg(addr, binary):
    for seg in binary.segments:
        if seg.virtual_size > 0 and \
           addr >= seg.virtual_address and \
           addr < seg.virtual_address + seg.virtual_size:
            return seg
    return None

def main():
    target_path = "./clade_section_decompressed.bin"
    target_file = open(target_path, "rb")
    modem_path = "./pixel_5_mar_2023/modem/modem.bin"
    # Collect necessary segments.
    modem_binary = lief.parse(modem_path)
    # Create d page
    out_addr = 0xd8000000
    size = os.stat(target_path).st_size
    x = lief.ELF.Segment()
    x.type = lief.ELF.SEGMENT_TYPES.LOAD
    x.physical_address = out_addr
    x.physical_size = size
    x.virtual_address = out_addr
    x.virtual_size = size
    x.add(lief.ELF.SEGMENT_FLAGS.R)
    x.add(lief.ELF.SEGMENT_FLAGS.W)
    x.add(lief.ELF.SEGMENT_FLAGS.X)
    x.alignment = 4
    x.content = list(target_file.read())
    # Inject segments
    print("Adding decompressed section...")
    modem_binary.add(x)
    print("Writing to disk...")
    modem_binary.write(f"./modem_decompressed.bin")
    print("Done!")

if __name__ == "__main__":
    main()
