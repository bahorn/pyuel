"""
Python + ctypes implementation of a ulexec()
"""

import sys
import math

from elftools.elf.elffile import ELFFile
import ctypes
import time

from keystone import Ks, KS_ARCH_X86, KS_MODE_64

SIGALRM = 14

PROT_READ = 0x01
PROT_WRITE = 0x02
PROT_EXEC = 0x04

MAP_PRIVATE = 0x02
MAP_ANONYMOUS = 0x20
MAP_FIXED = 0x10


KB = 1024
MB = 1024 * KB
STACK_SIZE = 10 * MB

PAGE_SIZE = 4096


def become_page(size):
    return math.ceil(size / PAGE_SIZE) * PAGE_SIZE


def in_range(value, start, end):
    return (start <= value) and (value <= end)


def loader(address):
    """
    Changes the stack, and jumps to the code
    """

    ks = Ks(KS_ARCH_X86, KS_MODE_64)
    loader_code = f"""
        push {address}
        ret
    """
    encoding, count = ks.asm(loader_code)
    return bytearray(encoding)


def main():
    libc = ctypes.CDLL(None)

    libc.mmap.restype = ctypes.c_void_p
    libc.mprotect.restype = ctypes.c_int
    libc.memcpy.restype = ctypes.c_void_p
    libc.memset.restype = ctypes.c_void_p

    entrypoint = None

    # Map the payload in
    with open(sys.argv[1], 'rb') as f:
        elffile = ELFFile(f)
        base_entrypoint = elffile.header.e_entry

        for segment in elffile.iter_segments():
            vaddr = segment['p_vaddr']
            memsz = become_page(segment['p_memsz'])

            new_vaddr = 0x41420000

            if in_range(base_entrypoint, vaddr, vaddr + memsz):
                entrypoint = new_vaddr + base_entrypoint

            if segment['p_memsz'] == 0:
                continue

            flags = MAP_PRIVATE | MAP_ANONYMOUS

            if vaddr != 0:
                flags |= MAP_FIXED

            # Allocate
            res = libc.mmap(
                new_vaddr,
                1024,
                PROT_READ | PROT_WRITE,
                flags,
                0,
                0
            )

            if res == -1:
                raise Exception(f'{vaddr:x} {memsz} - MMAP Failed')

            print(hex(res))

            libc.memset(res, ctypes.c_int(0), memsz)
            # copy in
            segment_data = bytearray(segment.data())
            d_a = ctypes.c_char * len(segment_data)

            print(res, len(segment_data))

            libc.memcpy(
                res,
                ctypes.pointer(d_a.from_buffer(segment_data)),
                len(segment_data)
            )

            # Fix permissions
            es = PROT_EXEC if (segment['p_flags'] & 0x1) > 0 else 0
            ws = PROT_WRITE if (segment['p_flags'] & 0x2) > 0 else 0
            rs = PROT_READ if (segment['p_flags'] & 0x4) > 0 else 0

            libc.mprotect(
                res,
                memsz,
                es | ws | rs
            )

    if entrypoint is None:
        raise Exception("No entrypoint?")

    # Now our setup code

    target_addr = ctypes.c_ulonglong(0x51420000)
    target_size = 1024

    # Get some memory for our setup code
    setup_code = libc.mmap(
        target_addr,
        target_size,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
        0,
        0
    )

    # Copy the setup code in
    print('entrypoint: ', hex(entrypoint))
    data = loader(entrypoint)
    char_array = ctypes.c_char * len(data)

    libc.memcpy(
        setup_code,
        ctypes.pointer(char_array.from_buffer(data)),
        target_size
    )

    # Fix memory permissions
    libc.mprotect(
        setup_code,
        target_size,
        PROT_READ | PROT_EXEC
    )

    # Setup an inital stack
    stack = libc.mmap(
        0x00,
        STACK_SIZE,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        0,
        0
    )

    # Now create our initial stack

    print(hex(stack))

    # Take control
    libc.signal(SIGALRM, setup_code)
    libc.alarm(1)
    time.sleep(0x1)


if __name__ == "__main__":
    main()
