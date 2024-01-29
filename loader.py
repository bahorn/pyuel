"""
Python + ctypes implementation of a ulexec()
"""
import binascii
import os
import sys
import math
import struct
import base64
import json
import zlib

import ctypes

SIGALRM = 0x0e

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

libc = ctypes.CDLL(None)

# need to define these or the results will be narrowed down to 32bits in a
# lot of cases
libc.mmap.restype = ctypes.c_ulonglong
libc.mmap.argtypes = [
    ctypes.c_ulonglong,
    ctypes.c_size_t,
    ctypes.c_int,
    ctypes.c_int,
    ctypes.c_int,
    ctypes.c_ulonglong
]
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

libc.signal.argtypes = [ctypes.c_int, ctypes.c_ulonglong]


def become_page(size):
    return math.ceil(size / PAGE_SIZE) * PAGE_SIZE


def in_range(value, start, end):
    return (start <= value) and (value <= end)


def loader(address, stack):
    """
    Changes the stack, and jumps to the code
    """
    # from gen_asm.py
    template = binascii.unhexlify(
        '48bc58575655545352514831d248b84847464544434241ffe0'
    )
    t = template.replace(
        struct.pack('<Q', 0x4142434445464748),
        struct.pack('<Q', address)
    )
    t = t.replace(
        struct.pack('<Q', 0x5152535455565758),
        struct.pack('<Q', stack)
    )
    return bytearray(t)


class Stack:
    """
    Create a stack.
    """

    def __init__(self, size):
        self._base = libc.mmap(
            0x00,
            size,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS,
            -1,
            0
        )
        self._size = size
        self._res = bytearray(b'\x00' * size)
        self._pos = size

    def base(self):
        return self._base

    def pos(self):
        return self._base + self._pos

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
        diff = self._size - self._pos
        return self.push(b'\x00' * (diff % 16))

    def get(self):
        return self._res

    def copyin(self):
        """
        Copy the generated stack into the allocated memory.
        """
        char_array = ctypes.c_char * self.size()
        libc.memcpy(
            self.base(),
            ctypes.pointer(char_array.from_buffer(self.get())),
            self.size()
        )


class SHELFLoader:
    ARCH = 'x86_64'

    def __init__(self, data):
        self.load(data)

    def load(self, data):
        vaddr = data['vaddr']
        memsz = data['memsz']
        flags = MAP_PRIVATE | MAP_ANONYMOUS

        if vaddr != 0:
            flags |= MAP_FIXED

        # Allocate
        res = libc.mmap(
            vaddr,
            memsz,
            PROT_READ | PROT_WRITE,
            flags,
            -1,
            0
        )

        if res == -1:
            raise Exception('mmaping code Failed')

        libc.memset(res, 0, memsz)

        unpacked_data = bytearray(
            zlib.decompress(base64.b64decode(data['data']))
        )

        # copy in
        d_a = ctypes.c_char * len(unpacked_data)

        libc.memcpy(
            res,
            ctypes.pointer(d_a.from_buffer(unpacked_data)),
            len(unpacked_data)
        )

        # Fix permissions
        es = PROT_EXEC if data['perm_x'] else 0
        ws = PROT_WRITE if data['perm_w'] else 0
        rs = PROT_READ if data['perm_r'] else 0

        libc.mprotect(
            res,
            memsz,
            es | ws | rs
        )

        entrypoint = res + data['entrypoint']
        self._phdr_offset = res + vaddr + data['phdr']['offset']
        self._phdr_size = data['phdr']['size']
        self._phdr_num = data['phdr']['num']
        self._entrypoint = entrypoint

    def create_stack(self, argv, envv):
        # Now create our initial stack
        new_stack = Stack(STACK_SIZE)

        new_stack.push(b'HEREHEREHEREHERE')
        new_stack.push(b'\x00'*16)
        # Env
        at_execfn = new_stack.push_str('./fakename')

        env_addr = [
            new_stack.push_env_str(k, v) for k, v in envv.items()
        ]
        arg_addr = [new_stack.push_str(k) for k in argv]

        new_stack.pad()

        at_platform = new_stack.push_str(self.ARCH)
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
        new_stack.push_auxv(AT_ENTRY, self._entrypoint)
        new_stack.push_auxv(AT_FLAGS, 0)
        new_stack.push_auxv(AT_BASE, 0)
        new_stack.push_auxv(AT_PHNUM, self._phdr_num)
        new_stack.push_auxv(AT_PHENT, self._phdr_size)
        new_stack.push_auxv(AT_PHDR, self._phdr_offset)
        new_stack.push_auxv(AT_CLKTCK, 100)
        new_stack.push_auxv(AT_PAGESZ, PAGE_SIZE)
        new_stack.push_auxv(AT_SYSINFO_EHDR, libc.getauxval(AT_SYSINFO_EHDR))

        # push the env
        new_stack.push_int(0)
        for env in env_addr[::-1]:
            new_stack.push_int(env)

        # push the argv
        new_stack.push_int(0)
        for arg in arg_addr[::-1]:
            new_stack.push_int(arg)

        # argc
        new_stack.push_int(len(argv) - 1)

        new_stack.copyin()

        return new_stack

    def jump_to_code(self, stack):
        """
        Create a small stub to place the code at, and use that to transition
        control.
        """
        target_size = 4096

        # Get some memory for our setup code
        setup_code = libc.mmap(
            0,
            target_size,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS,
            -1,
            0
        )

        # Copy the setup code in
        print('entrypoint: ', hex(self._entrypoint))
        data = loader(self._entrypoint, stack.pos())
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
        libc.gsignal(SIGALRM)

    def run(self, argv, envv=os.environ):
        stack = self.create_stack(argv, envv)
        self.jump_to_code(stack)


def main():
    with open(sys.argv[1], 'rb') as f:
        data = json.load(f)
    sl = SHELFLoader(data)
    sl.run(['hello', 'world'], envv={'HOME': '/tmp'})


if __name__ == "__main__":
    main()
