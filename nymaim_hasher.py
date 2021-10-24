#! /usr/bin/python3
import sys
import rzpipe

def init_rizin(nymaim_path):

    rz = rzpipe.open(nymaim_path)

    # Init emul
    rz.cmd("e asm.emu=true")
    rz.cmd("e emu.str=true")
    rz.cmd("e asm.bits=32")
    rz.cmd("e asm.arch=x86")
    rz.cmd("e io.cache=true")

    # Init VM
    rz.cmd("aei")
    # Init stack
    rz.cmd("aeim")

    return rz

def get_str_hash(rz, str_2_hash):

    # init registers
    rz.cmd("dr eip=0x004062fb")
    rz.cmd("dr ebx=0")
    rz.cmd("dr edx=0x6eba5b41")
    rz.cmd("dr esi=0x00178100")
    rz.cmd(f"dr edi={len(str_2_hash)}")

    # Write exe string in memory
    w_str = ""
    for char in str_2_hash:
        w_str += char
        w_str += "\\x00"
    
    # Trailing 0
    w_str += "\\x00\\x00"
    
    rz.cmd(f"w {w_str} @ 0x00178100")
    
    # Emulate until end of loop
    rz.cmd("aecu 0x406346")

    # Hash is stored in EBX reg
    regs = rz.cmdj("drj")
    ebx = regs["ebx"]

    exe_hash = ebx
    exe_hash_xor = ebx ^ 0x102ef675
    
    str_hash = f"0x{exe_hash:X}"
    str_hash_xor = f"0x{exe_hash_xor:X}"

    return str_hash, str_hash_xor

if __name__ == "__main__":

    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <nymaim_exe> <strings_list>")
        exit(1)

    nymaim_path = sys.argv[1]
    list_file = sys.argv[2]

    rz = init_rizin(nymaim_path)

    # Get executable names
    strings_list = []
    with open(list_file, "r") as fd:
        strings_list = fd.readlines()

    for str_2_hash in strings_list:
        # Remove only trailing '\n'
        # Some strings contain trailing meaningful spaces 
        str_2_hash = str_2_hash.rstrip("\n")
        hashes = get_str_hash(rz, str_2_hash)
        print(f"'{str_2_hash}' --> {hashes}")
