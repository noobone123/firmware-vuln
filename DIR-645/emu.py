import sys
sys.path.append("..")
from qiling import *
from qiling.const import *
from qiling.os.const import *
from qiling.extensions import trace
from unicorn import *
from capstone import *
from pwnlib.elf import *

md = Cs(CS_ARCH_MIPS, CS_MODE_32 + CS_MODE_LITTLE_ENDIAN)

#! IMPORTANT: enable detail mode for capstone, otherwise can not get operands of inst
md.detail = True

MAIN_ADDR = 0x0402770
HEDWIGCGI_MAIN = 0x0040bfc0
HEDWIGCGI_MAIN_END = 0x0040c594
SESS_GET_UID = 0x004083f0

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
    return addrsym_map


def if_external_addr(ql: Qiling, addr: int, pie_base = None):
    try:
        lib_addr_min = min(info["base"] for info in lib_maps)

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
    for lib_map in lib_maps:
        for s_addr in lib_map["addrsym_map"].keys():
            if addr == s_addr:
                return lib_map["addrsym_map"][s_addr]
    
    ql.log.warning(f"Can not find symbol for address: {hex(addr)}")
    return "?"
    
def trace_report(inst: CsInsn, callee_name: str):
    global last_report
    global current_report
    
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
        current_report["callee"] = callee_name
        current_report["count"] = 1
        current_report["log"] = f"{hex(inst.address)}: {inst.mnemonic} -> {callee_name}"

        print(current_report["log"])
        print("\tcount: %d" % (current_report["count"]))

        last_report = current_report

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
            
            # if the call target is external function, we should not trace it
            if not trace_externl_func:
                if if_external_addr(ql, address):
                    return
            
            call_target_op = inst.operands[0]
            assert call_target_op.type == CS_OP_REG
            call_target_reg_name = inst.reg_name(call_target_op.reg)
            assert call_target_reg_name == "t9"
            call_target = ql.arch.regs.read(call_target_reg_name)
            trace_report(inst, resolve_addr2sym(ql, call_target))

    ql.hook_code(__trace_hook)


def main_hook(ql: Qiling):
    ql.log.warning("** At [main] **")

    # init the mapinfo
    formated_map_info = parse_mapinfo(ql)

    # get the executable symbol map
    global exeu_addrsym_map
    exeu_addrsym_map = create_symbol_map(binary_path)

    # get the lib path and lib base address
    global lib_maps
    lib_set = set()

    for mapinfo in formated_map_info:
        # ld is excluded by following condition
        if ("lib" in mapinfo["label"] and "[mmap]" in mapinfo["label"]) or ("ld-uClibc" in mapinfo["label"]):
            lib_name = mapinfo["label"].replace("[mmap]", "").strip()
            lib_path = rootfs + "/lib" + "/" + lib_name
            lib_set.add((lib_path, ql.mem.get_lib_base(lib_name)))
    
    for lib in lib_set:
        lib_maps.append({
            "path": lib[0],
            "base": lib[1],
            "addrsym_map": create_symbol_map(lib[0], lib[1])
        })

def my_sandbox(path, rootfs):

    def strcpy_hook(ql: Qiling):
        param_dict = {
            "dst": POINTER,
            "src": STRING
        }
        params = ql.os.resolve_fcall_params(param_dict)
        
        print("dst: %s" % (hex(params["dst"])))
        print("src: %s" % (params["src"]))

        return 1


    buffer = "uid=%s" % (b"A" * 1041 + b"1111")
    required_env = {
        "REQUEST_METHOD": "POST",
        "HTTP_COOKIE": buffer
    }

    ql = Qiling(path, rootfs, env = required_env)
    ql.add_fs_mapper('/tmp', '/var/tmp')        # Maps hosts /tmp to /var/tmp
    ql.hook_address(main_hook, MAIN_ADDR)
    ql.hook_address(lambda ql: ql.log.warning("** At [hedwigcgi_main] **"), HEDWIGCGI_MAIN)
    ql.hook_address(lambda ql: ql.log.warning("** At [sess_get_uid] **"), SESS_GET_UID)


    # ql.hook_address(hook_sess_get_uid, SESS_GET_UID)
    ql.os.set_api("strcpy", strcpy_hook, QL_INTERCEPT.ENTER)
    # ql.debugger = True

    trace_callback(ql, trace_externl_func = False)

    ql.log.setLevel("WARNING")
    ql.run()

if __name__ == "__main__":
    binary_path = "_DIR645A1_FW103RUB08.bin.extracted/squashfs-root/htdocs/hedwig.cgi"
    rootfs = "_DIR645A1_FW103RUB08.bin.extracted/squashfs-root"

    exeu_addrsym_map = {}
    lib_maps = []

    last_report = {}
    current_report = {}

    try:
        my_sandbox([binary_path], rootfs)
    except Exception as e:
        print(e)