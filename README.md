# qualcomm_baseband_scripts
Collection of scripts for reversing Qualcomm baseband / modem firmware

All offsets/addresses in the scripts have been updated to the Pixel 5 March firmware and need to be changed if using a different version.

# Merging
`merge_modem_firmware.py` Merges all of the `modem.b**` (`modem.b00`, `modem.b01`, etc.) files into a single monolithic binary named `modem.bin`. This makes it much easier to load into IDA and Ghidra.

# Decompression
`clade_extractor` and `dlpage_extractor` decompress the CLADE and Delta compressed sections.

`clade_extractor` is compiled to x86 (or your native arch) and will output the decompressed section to a file. As far as I know, there is no publicly available information or code published for Qualcomm CLADE compression aside from the [patent](https://patents.google.com/patent/US9300320B2/en). CLADE has replaced q6zip as the main compression method for user-mode modules and is a pain to reverse because it's mostly implemented in hardware.

`dlpage_extractor` is compiled for Hexagon and emulated in QEMU (as previous works have done). The decompressed memory will then need to be dumped in GDB. There is also code here for the old q6zip compression method, although this is no longer used on newer modem binaries. The delta section only has a couple diag command handler structs, so the CLADE compressed section is where most of the meat is. I wouldn't even bother with this on newer binaries, it's only here for older ones.

# Merging Again
Once you have the decompressed CLADE section, you can run `add_decompressed_section_to_modem_bin.py` to add it to `modem.bin`. This can be done manually in IDA and Ghidra, but this script makes it a bit easier to load and backup the final binaries.

# Reversing
`qshrink4_qdb_ghidra_script.py` decodes all calls to `msg_v4_send*` into their respective debug strings. It will add a comment to the top of every function that uses them. These debug strings are incredibly useful for reversing as they always give the file name and some context for the function. To make it even better, they sometimes contain function names, variable names, and more. Check the file path that's being opened for help on getting the qdb file from the Pixel 5 firmware file. Just keep binwalk extracting until you get what you need.

`diag_handler_locator_ghidra_script.py` locates and rename all diag command handler functions into a `<op1>_<op2>_diag_cmd_handler` naming scheme so that they're easier to search for in Ghidra.

# Credit
A couple of the scripts have code taken from other sources. I've tried to give credit for everything, but I may have forgotten one or two. Please let me know if I used your code and forgot to credit you.

If this repo helped you, please ⭐ it!
