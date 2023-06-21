compile_dlpage_extractor.sh
./dlpage_modem_inject_pixel_5.sh
gdb qemu-hexagon --args ./dlpage_extractor

### once ran and inside gdb ###
#dump binary memory delta.bin 0xd0389000 0xd0389030