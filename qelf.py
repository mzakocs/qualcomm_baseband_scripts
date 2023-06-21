import struct

# Taken from https://github.com/tewilove/QCOM_dlpager_v2/blob/main/modem_inject.py

OFFSET_E_PHOFF = 0x1C
OFFSET_E_PHENTSIZE = 0x2A
OFFSET_E_PHNUM = 0x2C
PHDR_SIZE = 0x20
OFFSET_P_OFFSET = 0x4
OFFSET_P_FILESZ = 0x10

QEMU_EXEC_PAGE_SIZE = 0x10000
QEMU_EXEC_PAGE_MASK = (QEMU_EXEC_PAGE_SIZE - 1)

class QElf:
    def __init__(self, path):
        self.path = path
        self.data = open(path, "rb").read()
        e_phoff, = struct.unpack("<I", self.data[OFFSET_E_PHOFF:OFFSET_E_PHOFF+4])
        self.e_phentsize, = struct.unpack("<H", self.data[OFFSET_E_PHENTSIZE:OFFSET_E_PHENTSIZE+2])
        self.e_phnum, = struct.unpack("<H", self.data[OFFSET_E_PHNUM:OFFSET_E_PHNUM+2])
        self.phdr = self.data[e_phoff:e_phoff+self.e_phentsize*self.e_phnum]
        self.p_offset = len(self.data)
        # Check if ELF file was modified by this
        if e_phoff+self.e_phentsize*self.e_phnum == len(self.data):
            self.p_offset -= self.e_phentsize*self.e_phnum
            self.data = self.data[0:self.p_offset]

    def add(self, seg):
        if ((seg.virtual_address - self.p_offset) & QEMU_EXEC_PAGE_MASK) != 0:
            padding = QEMU_EXEC_PAGE_SIZE + \
                (seg.virtual_address & QEMU_EXEC_PAGE_MASK) - \
                (self.p_offset & QEMU_EXEC_PAGE_MASK)
            if padding > QEMU_EXEC_PAGE_SIZE:
                padding -= QEMU_EXEC_PAGE_SIZE
            self.data += b"\x00" * padding
            self.p_offset += padding
        p_filesz = len(seg.content)
        self.phdr += \
            struct.pack("<IIIIIIII", \
                1, \
                self.p_offset, \
                seg.virtual_address, \
                seg.physical_address, \
                p_filesz, \
                seg.virtual_size, \
                7, \
                seg.alignment)
        if p_filesz > 0:
            self.data += seg.content
            self.p_offset += p_filesz
        self.e_phnum += 1

    def write(self):
        # Make PT_PHDR aligned
        if (self.p_offset % QEMU_EXEC_PAGE_SIZE) != 0:
            padding = QEMU_EXEC_PAGE_SIZE - (self.p_offset % QEMU_EXEC_PAGE_SIZE)
            self.data += b"\x00" * padding
            self.p_offset += padding
        # Fix ELF header
        print("Fixing ELF header...")
        self.e_phnum += 1
        self.data = self.data[:OFFSET_E_PHNUM] + \
            struct.pack("<H", self.e_phnum) + self.data[OFFSET_E_PHNUM+2:]
        self.data = self.data[:OFFSET_E_PHOFF] + \
            struct.pack("<I", self.p_offset) + self.data[OFFSET_E_PHOFF+4:]
        # Fix program header
        base = 0
        i = 0
        print("Fixing program header...")
        while i < len(self.phdr):
            p_type, _, p_vaddr = struct.unpack("<III", self.phdr[i:i+12])
            if p_type == 1:
                base = p_vaddr
                break
            i += self.e_phentsize
        pt_load = struct.pack("<IIIIIIII", \
            1, \
            self.p_offset, \
            base + self.p_offset, \
            base + self.p_offset, \
            self.e_phnum*self.e_phentsize, \
            self.e_phnum*self.e_phentsize, \
            4, \
            QEMU_EXEC_PAGE_SIZE)
        self.phdr += pt_load
        i = 0
        print("Packing memory...")
        print(self.e_phentsize)
        while i < len(self.phdr):
            p_type, = struct.unpack("<I", self.phdr[i:i+4])
            if p_type == 6:
                pt_phdr = struct.pack("<IIIIIIII", \
                    6, \
                    self.p_offset, \
                    base + self.p_offset, \
                    base + self.p_offset, \
                    self.e_phnum*self.e_phentsize, \
                    self.e_phnum*self.e_phentsize, \
                    4, \
                    4)
                print(f"Writing {hex(i)}")
                self.phdr = self.phdr[:i] + \
                    pt_phdr + self.phdr[i+self.e_phentsize:]
                break
            i += self.e_phentsize
        self.data += self.phdr
        with open(self.path, "wb") as f:
            f.write(self.data)