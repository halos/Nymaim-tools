# IDA python scrupt to 'unwrap' Nymaim's function calling obfuscation

def get_wrapper_type(wrapper):
    
    MakeCode(wrapper)

    op_types = ["sub", "xor", "add"]

    op_addr = wrapper + 7
    mnem = GetMnem(op_addr)

    if mnem == "mov":
        mnem = GetMnem(op_addr + 6)

    if mnem in op_types:
        return mnem

    else:
        print("Unexpected operation '%s' in wrapper at %s" % (mnem, hex(wrapper)))
        return None

# Method to look for 
def find_wrappers():

    wrappers = []
    
    wrapper_patterns = [
        "55 89 e5 50 8b 45 04 89 45 10 8b 45 0c ? ? ? e9",
        "55 89 e5 50 8b 45 0c ? ? ? e9"
    ]

    base = idaapi.get_imagebase() + 1024

    for patt in wrapper_patterns:
        while True:
            ea = FindBinary(base, SEARCH_DOWN, patt);
            
            if ea == BADADDR:
                break

            base = ea + 1
            wrappers.append(ea)

    return wrappers

def my_patch_bytes(patch_addr, patch_bytes):

    for offset, patch in enumerate(patch_bytes):
        idaapi.patch_byte(patch_addr + offset, patch)

def patch_wrapper_call(wrapper_call, wrap_type):
    
    if not check_wrapper_caller(wrapper_call):
        return

    # Get pushed DWORDs
    dw1 = Dword(wrapper_call - 9)
    dw2 = Dword(wrapper_call - 4)
    
    # Calculate real offset
    if wrap_type == "add":
        real_offset = dw1 + dw2
    elif wrap_type == "xor":
        real_offset = dw1 ^ dw2
    else: #elif wrap_type == "sub":
        real_offset = dw1 - dw2

    call_addr = real_offset + wrapper_call + 5
    call_addr &= 0xFFFFFFFF

    print("[i] Patching call @ %s" % (hex(wrapper_call)))
    
    my_patch_bytes(wrapper_call - 11, [0x90])

    # Patch 1st push
    my_patch_bytes(wrapper_call - 10, [0x90, 0x90, 0x90, 0x90, 0x90]) # 4 * NOP
    
    # Patch 2nd push
    my_patch_bytes(wrapper_call - 5, [0x90, 0x90, 0x90, 0x90, 0x90]) # 5 * NOP
    
    # Patch call
    new_inst = "call %d" % (call_addr)
    asm_ok, call_bytes_str = Assemble(wrapper_call, new_inst)
    if not asm_ok:
        print("[!] Error assembling '%s'" % (new_inst))
        return

    call_bytes = map(ord, call_bytes_str)
    my_patch_bytes(wrapper_call, call_bytes)
    print("[+] CALL fixed @ %s" % (hex(wrapper_call)))

# Method to check if the supposed wrapper caller has 3 push intructions just before
# This way the script can be run safely several times
def check_wrapper_caller(caller_addr):
    
    if not GetMnem(caller_addr) == "call":
        return False

    if not GetMnem(caller_addr - 5) == "push":
        return False

    if not GetMnem(caller_addr - 10) == "push":
        return False

    if not GetMnem(caller_addr - 11) == "push":
        return False

    return True

# Main #

print("[i] Looking for CALL wrappers")

for wrapper in find_wrappers():
    
    #print("[i] Patching wrapper %s (%s)" % (hex(wrapper), w_type))
    
    w_type = get_wrapper_type(wrapper)

    if w_type is None:
        continue

    # Get XREFs to wrapper
    for wrapper_ref in XrefsTo(wrapper):
        patch_wrapper_call(wrapper_ref.frm, w_type)

    print("-" * 30)
