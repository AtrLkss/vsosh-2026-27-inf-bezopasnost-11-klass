"""Static PE inspection: strings, RIP-relative references and disassembly.

This script only reads the input file. It does not load or execute it.
"""
from pathlib import Path
import argparse
import re

import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_MEM, X86_REG_RIP

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("exe", type=Path)
action = parser.add_mutually_exclusive_group(required=True)
action.add_argument("--find", help="Find a UTF-8 string in the binary")
action.add_argument("--xref", type=lambda s: int(s, 0), help="RIP references to a file offset")
action.add_argument("--disasm", type=lambda s: int(s, 0), help="Disassemble from a file offset")
parser.add_argument("--length", type=lambda s: int(s, 0), default=0x100)
args = parser.parse_args()
data = args.exe.read_bytes()
pe = pefile.PE(data=data)
base = pe.OPTIONAL_HEADER.ImageBase
md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True

if args.find is not None:
    for match in re.finditer(re.escape(args.find.encode("utf-8")), data):
        address = base + pe.get_rva_from_offset(match.start())
        print(f"File offset {match.start():#x}; preferred VA {address:#x}")
elif args.xref is not None:
    target = base + pe.get_rva_from_offset(args.xref)
    for section in pe.sections:
        if not section.Characteristics & 0x20000000:
            continue
        for ins in md.disasm(section.get_data(), base + section.VirtualAddress):
            if any(op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP
                   and ins.address + ins.size + op.mem.disp == target
                   for op in ins.operands):
                print(f"{ins.address:#x}: {ins.mnemonic} {ins.op_str} -> {target:#x}")
else:
    address = base + pe.get_rva_from_offset(args.disasm)
    print(f"ImageBase {base:#x}; file offset {args.disasm:#x}; preferred VA {address:#x}")
    for ins in md.disasm(data[args.disasm:args.disasm + args.length], address):
        comment = []
        for operand in ins.operands:
            if operand.type == X86_OP_MEM and operand.mem.base == X86_REG_RIP:
                target = ins.address + ins.size + operand.mem.disp
                comment.append(f"RIP -> {target:#x}")
        suffix = " ; " + ", ".join(comment) if comment else ""
        print(f"{ins.address:016x}  {ins.mnemonic:9} {ins.op_str}{suffix}")
