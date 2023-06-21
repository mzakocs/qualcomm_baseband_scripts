# original source: https://github.com/bkerler/qc_modem_tools/blob/master/unify_trustlet

import sys
import os
import struct

ELF_HEADER_SIZE = 0x34
E_PHNUM_OFFSET = 0x2C
PHDR_SIZE = 0x20
P_FILESZ_OFFSET = 0x10
P_OFFSET_OFFSET = 0x4

def main():

	#Reading the arguments
	if len(sys.argv) != 4:
		print("USAGE: <TRUSTLET_DIR> <TRUSTLET_NAME> <OUTPUT_FILE_PATH>")
		return
	trustlet_dir = sys.argv[1]
	trustlet_name = sys.argv[2]
	output_file_path = sys.argv[3]

	#Reading the ELF header from the ".mdt" file
	mdt = open(os.path.join(trustlet_dir, "%s.mdt" % trustlet_name), "rb")
	elf_header = mdt.read(ELF_HEADER_SIZE)
	phnum = struct.unpack("<H", elf_header[E_PHNUM_OFFSET:E_PHNUM_OFFSET+2])[0]
	print("[+] Found %d program headers" % phnum)
	
	#Reading each of the program headers and copying the relevant chunk
	output_file = open(output_file_path, 'wb')
	for i in range(0, phnum):

		#Reading the PHDR
		print("[+] Reading PHDR %d" % i)
		phdr = mdt.read(PHDR_SIZE) 	
		p_filesz = struct.unpack("<I", phdr[P_FILESZ_OFFSET:P_FILESZ_OFFSET+4])[0] 
		p_offset= struct.unpack("<I", phdr[P_OFFSET_OFFSET:P_OFFSET_OFFSET+4])[0] 
		print("[+] Size: 0x%08X, Offset: 0x%08X" % (p_filesz, p_offset))

		if p_filesz == 0:
			print("[+] Empty block, skipping")
			continue #There's no backing block

		#Copying out the data in the block
		block = open(os.path.join(trustlet_dir, "%s.b%02d" % (trustlet_name, i)), 'rb').read()
		output_file.seek(p_offset, 0)
		output_file.write(block)

	mdt.close()
	output_file.close()

if __name__ == "__main__":
	main()