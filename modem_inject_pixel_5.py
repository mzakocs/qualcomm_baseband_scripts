#!/usr/bin/python

import sys
import lief

def to_seg(addr, binary):
    for seg in binary.segments:
        if seg.virtual_size > 0 and \
           addr >= seg.virtual_address and \
           addr < seg.virtual_address + seg.virtual_size:
            return seg
    return None

def main():
    if len(sys.argv) != 3:
        return
    target_path = sys.argv[1]
    target_elf = lief.parse(target_path)
    modem_path = sys.argv[2]
    # Collect necessary segments.
    modem_binary = lief.parse(modem_path)
    mdm_seg = []
    # Get all valid segments
    for seg in modem_binary.segments:
        if seg.physical_size > 0:
            mdm_seg.append(seg)
    # Create d page
    out_addr = 0xd8000000 + 0xd00000
    size = 0x10000000
    full_size = size
    x = lief.ELF.Segment()
    x.type = lief.ELF.SEGMENT_TYPES.LOAD
    x.physical_address = out_addr
    x.physical_size = full_size
    x.virtual_address = out_addr
    x.virtual_size = full_size
    x.add(lief.ELF.SEGMENT_FLAGS.R)
    x.add(lief.ELF.SEGMENT_FLAGS.W)
    x.add(lief.ELF.SEGMENT_FLAGS.X)
    x.alignment = 4
    d_page = x
    # Inject segments
    print("Adding modem pages...")
    for x in mdm_seg:
        print(str(x))
        target_elf.add(x)
    print("Adding DPage...")
    target_elf.add(d_page)
    print("Writing to disk...")
    target_elf.write(f"{target_path}_injected")
    print("Done!")

if __name__ == "__main__":
    main()
