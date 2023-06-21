// Offsets for Pixel 5 13.0.0 (TQ2A.230305.008.C1, Mar 2023) firmware
// Heavily inspired by this https://research.checkpoint.com/2021/security-probe-of-qualcomm-msm/

#include <stdint.h>

typedef void (* _q6zip_decompress) (uint32_t, uint32_t, uint32_t, uint32_t, uint32_t); 
void q6zip_decompress() {
	uint32_t out_buf = 0xD0000000;
	uint32_t in_buf = 0xCF600000;
	uint32_t in_buf_end = 0xCF70F3C9 + 0x3; // +0x3 to align to 4 bytes
	uint32_t dict = in_buf + 4;
	uint32_t index = dict+0x5000;
	uint32_t decompress_func_addr = 0xC05EB420;
	uint32_t out_buf_size = 0;
	uint32_t nb = *(uint16_t*)in_buf;
	for (uint32_t cb = 0; cb < nb; cb++) {
		uint32_t block_ptr = *(uint32_t*) (index + cb * 4);
		uint32_t block_size =
			cb + 1 < nb ?
			(*(uint32_t*) (index + (cb + 1) * 4) - block_ptr) :
			in_buf_end - block_ptr;
			
		uint32_t out_size = 0;
		((_q6zip_decompress) (decompress_func_addr)) (
			out_buf + out_buf_size, (uint32_t)(&out_size), block_ptr, block_size, dict);
			
		out_buf_size += out_size;
	}
}

typedef void (* _delta_decompress) (uint32_t, uint32_t, uint32_t);
void delta_decompress() {
	uint32_t out_buf = 0xD0000000;
	// uint32_t out_buf = 0xD0000000;
	uint32_t in_buf = 0xCF710000;
	uint32_t in_buf_end = 0xCF710128;
	uint32_t index = in_buf + 4;
	uint32_t decompress_func_addr = 0xC05EBBD0;
	uint32_t out_buf_size = 0;
	uint32_t nb = *(uint16_t*)in_buf;
	for (uint32_t cb = 0; cb < nb; cb++) {
		uint32_t block_ptr = *(uint32_t*) (index + cb * 4);
		uint32_t out_size = 0x1000;
		((_delta_decompress) (decompress_func_addr)) (block_ptr, out_buf + out_buf_size, out_size);
		out_buf_size += out_size;
	}
}

typedef void (* entrypoint_func) ();
int main() {
	// Newer binaries only have delta compression and clade, no q6zip
	delta_decompress();
	// make gdb stop here
	*((int *)0xBEEFBEEF) = 0xC0FFEE;
	return 0;
}
