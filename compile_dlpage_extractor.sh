# get hexagon-unknown-linux-musl-clang from https://github.com/quic/toolchain_for_hexagon
# hexagon_clang from hexagon sdk will not work
hexagon-unknown-linux-musl-clang -static -o dlpage_extractor -Wall dlpage_extractor_pixel_5.c