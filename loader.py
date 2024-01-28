"""
Python + ctypes implementation of a ulexec()
"""
import os
import sys
import math
import struct

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


# All the AUXV

AT_NULL = 0
AT_IGNORE = 1
AT_EXECFD = 2
AT_PHDR = 3
AT_PHENT = 4
AT_PHNUM = 5
AT_PAGESZ = 6
AT_BASE = 7
AT_FLAGS = 8
AT_ENTRY = 9
AT_NOTELF = 10
AT_UID = 11
AT_EUID = 12
AT_GID = 13
AT_EGID = 14
AT_PLATFORM = 15
AT_HWCAP = 16
AT_CLKTCK = 17
AT_SECURE = 23
AT_BASE_PLATFORM = 24
AT_RANDOM = 25
AT_HWCAP2 = 26
AT_RSEQ_FEATURE_SIZE = 27
AT_RSEQ_ALIGN = 28
AT_EXECFN = 31
AT_SYSINFO_EHDR = 33
AT_MINSIGSTKSZ = 51


def become_page(size):
    return math.ceil(size / PAGE_SIZE) * PAGE_SIZE


def in_range(value, start, end):
    return (start <= value) and (value <= end)


def loader(address, stack):
    """
    Changes the stack, and jumps to the code
    """
    ks = Ks(KS_ARCH_X86, KS_MODE_64)
    loader_code = f"""
        mov rsp, 0x{stack:08x}
        xor rdx, rdx
        mov rax, 0x{address:08x}
        jmp rax
    """
    encoding, count = ks.asm(loader_code)
    return bytearray(encoding)


class Stack:
    """
    generate a stack
    """

    def __init__(self, base, size):
        self._base = base
        self._size = size
        self._res = bytearray(b'\x00' * size)
        self._pos = size

    def base(self):
        return self._base

    def pos(self):
        return self._base - self._size + self._pos

    def size(self):
        return self._size

    def push(self, value):
        self._pos -= len(value)
        self._res[self._pos:self._pos + len(value)] = value
        return self.pos()

    def push_str(self, value):
        v = bytes(value, encoding='ascii') + b'\x00'
        return self.push(v)

    def push_env_str(self, key, value):
        return self.push_str(f'{key}={value}')

    def push_auxv(self, key, value):
        value = struct.pack('<QQ', key, value)
        return self.push(value)

    def push_int(self, value):
        return self.push(struct.pack('<Q', value))

    def pad(self):
        """
        align to 16 byte boundry
        """
        diff = self._base + self._size - self._pos
        return self.push(b'\x00' * (diff % 16))

    def get(self):
        return self._res


def main():
    libc = ctypes.CDLL(None)

    # need to define these or the results will be narrowed down to 32bits in a
    # lot of cases
    libc.mmap.argtypes = [
        ctypes.c_ulonglong,
        ctypes.c_size_t,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_ulonglong
    ]
    libc.mmap.restype = ctypes.c_ulonglong
    libc.mprotect.restype = ctypes.c_int
    libc.mprotect.argtypes = [
        ctypes.c_ulonglong,
        ctypes.c_size_t,
        ctypes.c_int
    ]
    libc.memcpy.restype = ctypes.c_ulonglong
    libc.memcpy.argtypes = [
        ctypes.c_ulonglong, ctypes.c_void_p, ctypes.c_size_t
    ]
    libc.memset.restype = ctypes.c_ulonglong
    libc.memset.argtypes = [
        ctypes.c_ulonglong, ctypes.c_int, ctypes.c_size_t
    ]

    libc.getauxval.restype = ctypes.c_ulong
    libc.getauxval.argtypes = [ctypes.c_ulong]

    entrypoint = None
    phdr_offset = 0
    phdr_size = 0
    phdr_num = 0

    # Map the payload in
    with open(sys.argv[1], 'rb') as f:
        elffile = ELFFile(f)
        base_entrypoint = elffile.header.e_entry
        phdr_offset = elffile.header.e_phoff
        phdr_size = elffile.header.e_phentsize
        phdr_num = elffile.header.e_phnum

        for segment in elffile.iter_segments(type='PT_LOAD'):
            vaddr = segment['p_vaddr']
            memsz = become_page(segment['p_memsz'])

            if segment['p_memsz'] == 0:
                continue

            flags = MAP_PRIVATE | MAP_ANONYMOUS

            if vaddr != 0:
                flags |= MAP_FIXED

            # Allocate
            res = libc.mmap(
                0,
                memsz,
                PROT_READ | PROT_WRITE,
                flags,
                -1,
                0
            )

            if res == -1:
                raise Exception(f'{vaddr:x} {memsz} - MMAP Failed')

            libc.memset(res, 0, memsz)

            # copy in
            segment_data = bytearray(segment.data())[:memsz]
            d_a = ctypes.c_char * len(segment_data)

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

            if in_range(base_entrypoint, vaddr, vaddr + memsz):
                entrypoint = res + vaddr + base_entrypoint
                phdr_offset += res + vaddr

            # Should only be one PT_LOAD segment
            break

    if entrypoint is None:
        raise Exception("No entrypoint?")

    # Setup an inital stack
    stack = libc.mmap(
        0x00,
        STACK_SIZE,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0
    )

    argv = ['hello', 'world']
    envv = [('HOME', '/tmp')]

    # Now create our initial stack
    new_stack = Stack(stack + STACK_SIZE, STACK_SIZE)

    new_stack.push(b'HEREHEREHEREHERE')
    new_stack.push(b'\x00'*16)
    # Env
    at_execfn = new_stack.push_str('./fakename')

    env_addr = [new_stack.push_env_str(k, v) for k, v in envv] + [0]
    arg_addr = [new_stack.push_str(k) for k in argv] + [0]

    new_stack.pad()

    at_platform = new_stack.push_str('x86-64')
    at_random = new_stack.push(os.urandom(16))
    new_stack.pad()

    # Auxv
    new_stack.push_auxv(AT_NULL, 0)
    new_stack.push_auxv(AT_PLATFORM, at_platform)
    new_stack.push_auxv(AT_EXECFN, at_execfn)
    new_stack.push_auxv(AT_RANDOM, at_random)
    new_stack.push_auxv(AT_SECURE, 0)
    new_stack.push_auxv(AT_EGID, os.getegid())
    new_stack.push_auxv(AT_GID, os.getgid())
    new_stack.push_auxv(AT_EUID, os.geteuid())
    new_stack.push_auxv(AT_UID, os.getuid())
    new_stack.push_auxv(AT_ENTRY, entrypoint)
    new_stack.push_auxv(AT_FLAGS, 0)
    new_stack.push_auxv(AT_BASE, 0)
    new_stack.push_auxv(AT_PHNUM, phdr_num)
    new_stack.push_auxv(AT_PHENT, phdr_size)
    new_stack.push_auxv(AT_PHDR, phdr_offset)
    new_stack.push_auxv(AT_CLKTCK, 100)
    new_stack.push_auxv(AT_PAGESZ, PAGE_SIZE)
    new_stack.push_auxv(AT_SYSINFO_EHDR, libc.getauxval(AT_SYSINFO_EHDR))

    # push the env
    for env in env_addr[::-1]:
        new_stack.push_int(env)

    # push the argv
    for arg in arg_addr[::-1]:
        new_stack.push_int(arg)

    # argc
    new_stack.push_int(len(argv) - 1)

    # Copy it to its new home
    char_array = ctypes.c_char * new_stack.size()
    libc.memcpy(
        stack,
        ctypes.pointer(char_array.from_buffer(new_stack.get())),
        new_stack.size()
    )

    # Now our setup code

    target_addr = ctypes.c_ulonglong(0x41420000)
    target_size = 1024

    # Get some memory for our setup code
    setup_code = libc.mmap(
        target_addr,
        target_size,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
        -1,
        0
    )

    # Copy the setup code in
    print('entrypoint: ', hex(entrypoint))
    data = loader(entrypoint, new_stack.pos())
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

    # Take control
    libc.signal(SIGALRM, setup_code)
    libc.alarm(1)
    time.sleep(0x1)


if __name__ == "__main__":
    main()
