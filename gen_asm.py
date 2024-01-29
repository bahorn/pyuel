import binascii
from keystone import Ks, KS_ARCH_X86, KS_MODE_64


def loader(address, stack):
    """
    Changes the stack, and jumps to the code
    """
    ks = Ks(KS_ARCH_X86, KS_MODE_64)
    print(hex(stack))
    loader_code = f"""
        mov rsp, 0x{stack:08x}
        xor rdx, rdx
        mov rax, 0x{address:08x}
        jmp rax
    """
    encoding, count = ks.asm(loader_code)
    return bytearray(encoding)


def main():
    res = loader(0x4142434445464748, 0x5152535455565758)
    print(binascii.hexlify(res))


if __name__ == "__main__":
    main()
