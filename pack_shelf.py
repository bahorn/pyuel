"""
Pack an SHELF, so we don't need to include ELFtools as a dep in the main loader
"""
import json
import base64
import math
import sys
import zlib
from elftools.elf.elffile import ELFFile

PAGE_SIZE = 4096


def become_page(size):
    return math.ceil(size / PAGE_SIZE) * PAGE_SIZE


def in_range(value, start, end):
    return (start <= value) and (value <= end)


def pack_elf(f):
    elffile = ELFFile(f)
    base_entrypoint = elffile.header.e_entry
    phdr_offset = elffile.header.e_phoff
    phdr_size = elffile.header.e_phentsize
    phdr_num = elffile.header.e_phnum

    data = None
    memsz = 0
    vaddr = 0
    perm_r = False
    perm_w = False
    perm_x = False
    for segment in elffile.iter_segments(type='PT_LOAD'):
        data = segment.data()
        vaddr = segment['p_vaddr']
        memsz = segment['p_memsz']
        perm_x = (segment['p_flags'] & 0x1) > 0
        perm_w = (segment['p_flags'] & 0x2) > 0
        perm_r = (segment['p_flags'] & 0x4) > 0
        break

    elf_struct = {
        'entrypoint': int(base_entrypoint),
        'phdr': {
            'offset': int(phdr_offset),
            'size': int(phdr_size),
            'num': int(phdr_num)
        },
        'vaddr': int(vaddr),
        'data': base64.b64encode(zlib.compress(data)).decode('ascii'),
        'memsz': int(memsz),
        'perm_r': perm_r,
        'perm_w': perm_w,
        'perm_x': perm_x
    }

    return elf_struct


def main():
    with open(sys.argv[1], 'rb') as f:
        print(json.dumps(pack_elf(f)))


if __name__ == "__main__":
    main()
