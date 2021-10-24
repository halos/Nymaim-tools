#! /usr/bin/python3
import sys
import shutil
import rzpipe

## Call wrappers ###

def get_wrapper_type(rz, wrapper_offset):
    
    wrapper_types = ["sub", "xor", "add"]

    rz.cmd(f"s {wrapper_offset}+7")
    opcode_info = rz.cmdj("aoj")[0]
    mnem = opcode_info["mnemonic"]

    if mnem == "mov":
        rz.cmd(f"s {wrapper_offset} + 7 + 6")
        opcode_info = rz.cmdj("aoj")[0]
        mnem = opcode_info["mnemonic"]

    if mnem in wrapper_types:
        return mnem

    else:
        print("Unexpected operation '%s' in wrapper at %s" % (mnem, wrapper_offset))
        return None

# Method to look for CALL wrappers
def find_wrappers(rz):

    wrappers = []
    
    wrapper_patterns = [
        "55 89 e5 50 8b 45 04 89 45 10 8b 45 0c .. .. .. e9",
        "55 89 e5 50 8b 45 0c .. .. .. e9"
    ]

    for patt in wrapper_patterns:
        wrapper_search = rz.cmdj(f"/xj {patt}")
        wrappers += [wrapper["offset"] for wrapper in wrapper_search]

    print(f"[i] {len(wrappers)} function wrappers found")

    return wrappers

def patch_wrapper_call(rz, wrapper_call, wrap_type):
    
    #print(f"[+] Scanning CALL @ 0x{wrapper_call:x}")
    if not check_wrapper_caller(rz, wrapper_call):
        return

    # Get pushed DWORDs
    pushes = rz.cmdj(f"aoj 2 @ {wrapper_call} - 10")
    
    dw1 = pushes[0]["opex"]["operands"][0]["value"]
    dw2 = pushes[1]["opex"]["operands"][0]["value"]
    
    # Calculate real offset
    if wrap_type == "add":
        real_offset = dw1 + dw2
    elif wrap_type == "xor":
        real_offset = dw1 ^ dw2
    else: #elif wrap_type == "sub":
        real_offset = dw1 - dw2

    call_addr = real_offset + wrapper_call + 5
    call_addr &= 0xFFFFFFFF

    #print(f"[i] Patching call @ 0x{wrapper_call:x}")
    
    # Patch call
    rz.cmd(f"wa call {call_addr} @ {wrapper_call}")

    # NOP 9 bytes (1 + 5 + 5) - 2 (jmp)
    rz.cmd(f"wx 909090909090909090 @ {wrapper_call} - 9")

    # Write jump instead of nops to ease disassemblers analysis
    jmp_addr = wrapper_call - 11
    rz.cmd(f"wa jmp {wrapper_call} @ {jmp_addr}")

    #print(f"[+] CALL fixed @ 0x{wrapper_call:x}")

# Method to check if the supposed wrapper caller has 3 push intructions just before
# This way the script can be run safely several times
def check_wrapper_caller(rz, caller_addr):
    
    # Check push/push/push/call
    #print(f"[i] Checking caller 0x{caller_addr:x}")

    # First push is 11 bytes before the call
    caller = rz.cmdj(f"aoj 4 @ {caller_addr} - 11")

    # If caller_addr-11 is not a 'push', but it is not a full instrucion,
    # caller list fill be empty
    if not caller:
        return

    if caller[0]["mnemonic"] != "push":
        return False

    if caller[1]["mnemonic"] != "push":
        return False

    if caller[2]["mnemonic"] != "push":
        return False

    if caller[3]["mnemonic"] != "call":
        return False

    return True

def remove_call_wrappers(rz):

    print("[i] >>> Looking for CALL wrappers <<<\n")

    for wrapper in find_wrappers(rz):
        
        print(f"[i] Analyzing wrapper 0x{wrapper:X}")

        w_type = get_wrapper_type(rz, wrapper)

        if w_type is None:
            continue

        print(f"[i] Type: {w_type}")

        # Get XREFs to wrapper
        xrefs = rz.cmdj(f"axtj @ {wrapper}")
        print(f"[i] {len(xrefs)} calls to this wrapper")
        print(f"[.] Patching...")

        for wrapper_ref in xrefs:
            patch_wrapper_call(rz, wrapper_ref["from"], w_type)

        print("-" * 30)

### Reg push ###

def remove_reg_push_functions(rz):

    entry_xrefs = None
    value_reg = {}
    patt = "83 7c 24 04 .. 0f 85 .. .. .. .. 89 .. 24 04 c3"

    print("\n\n[i] >>> Looking for push-reg calls <<<\n")

    arg_checkers = rz.cmdj(f"/xj {patt}")

    for arg_checker in arg_checkers:

        ac_offset = arg_checker["offset"]
        opcodes = rz.cmdj(f"aoj 3 @ {ac_offset}")

        value = opcodes[0]["val"]
        reg = opcodes[2]["opex"]["operands"][1]["value"]
        
        value_reg[value] = reg

        # Checker with more than 1 ref will be the entry checker
        # This is to get the addresses to be patched
        xrefs = rz.cmdj(f"axtj @ {ac_offset}")
        if len(xrefs) > 1:
            entry_checker = arg_checker
            entry_xrefs = xrefs

    print("[i] Value-Register equivalences")
    for val, reg in value_reg.items():
        print(f"[ ]\t0x{val:x} --> {reg}")
    
    print()
    print(f"[i] Patching {len(entry_xrefs)} calls")

    for reg_push in entry_xrefs:
        patch_reg_push(rz, value_reg, reg_push)


def patch_reg_push(rz, value_reg, reg_push):

    if reg_push["type"] != "CALL":
        return

    patch_addr = reg_push["from"] - 2 # - 2 to overwrite the "push <num>"
    jmp_addr = patch_addr + 1

    pushed_val = rz.cmdj(f"aoj @ {patch_addr}")[0]["val"]
    pushed_reg = value_reg[pushed_val]

    rz.cmd(f"wa push {pushed_reg} @ {patch_addr}")
    rz.cmd(f"wx 90909090 @ {jmp_addr} + 2")

    # Write jump instead of nops to ease disassemblers analysis
    addr_to = reg_push["from"] + 5
    rz.cmd(f"wa jmp {addr_to} @ {jmp_addr}")


# Main #

if __name__ == "__main__":

    if len(sys.argv) != 2:
        print("Usage: {} <nymaim_exe>".format(sys.argv[0]))
        exit(1)

    nymaim_in = sys.argv[1]
    nymaim_out = nymaim_in + ".deobf"

    # Create an unpacked copy
    print(f"[i] Unpacking sample into {nymaim_out}")
    shutil.copyfile(nymaim_in, nymaim_out)
    rz = rzpipe.open(nymaim_out, ["-w"])
    rz.cmd('aaa')
    # maybe 'aac' is more efficient

    # Deobfuscate call wrappers
    remove_call_wrappers(rz)

    # Deobfuscate register pushes
    remove_reg_push_functions(rz)

    print("[+] Done!")
    