# SPDX-License-Identifier: BSD-2-Clause
# @category Typhunix

from ghidra.program.model.symbol import *
import json


def get_all_symbols():
    """gets all symbols defined in the firmware with an address associated with it
    """
    out_symbols = []
    data_types = dict()
    data_type_xrefs = dict()

    for sym in set(currentProgram.getSymbolTable().getAllSymbols(True)):
        # where args are [{"name": "param1", "type": "int"}]
        out_sym = {"name": str(sym.getName(True)), "address": "0x" + str(sym.getAddress()), "type": "", "args": [], "len": 0}

        # see if this is a datatype
        data = currentProgram.getListing().getDataAt(sym.getAddress())
        if data:
            out_sym["type"] = str(data.getBaseDataType().getName())
            out_sym["len"] = data.getBaseDataType().getLength()
        else:
            # check if this is a function
            func = currentProgram.getListing().getFunctionAt(sym.getAddress())
            if func:
                out_sym["type"] = "function"
                out_sym["len"] = func.getBody().getMaxAddress().getUnsignedOffset() - func.getBody().getMinAddress().getUnsignedOffset()

                # get the function arguments and their respective data types
                args = []
                for arg in func.getParameters():
                    out_arg = {}
                    arg_type = arg.getFormalDataType()
                    out_arg["type"] = arg_type.getName()
                    out_arg["name"] = arg.getName()
                    if arg.isRegisterVariable():
                        out_arg["source"] = arg.getRegister().getName()
                    elif arg.isStackVariable():
                        out_arg["source"] = "sp + %d" % arg.getStackOffset()
                    args.append(out_arg)
                out_sym["args"] = args

                # get the address of the last instruction in the functions
                last_insn_addr = 0x0
                # first get the first insn for the function
                insn = currentProgram.getListing().getCodeUnitAt(sym.getAddress())
                prev = None
                while insn and int(str(insn.getAddress()), 16) < int(str(sym.getAddress()), 16) + out_sym["len"]:
                    prev = insn
                    insn = insn.next
                # last instruction in the function
                insn = prev
                if insn: # in case of 0 len func
                    last_insn_addr = "0x" + str(insn.getAddress())

                out_sym["last_insn"] = last_insn_addr
            else:
                # this is probably just a label, check if it is
                if sym.getSymbolType() == SymbolType.LABEL:
                    out_sym["type"] = "label"

        out_symbols.append(out_sym)
    return out_symbols

symbols = get_all_symbols()

outfile = getState().getEnvironmentVar("OUTFILE")
while not outfile:
    outfile = askFile("FILE", "Choose file to dump symbols to:")
print "writing symbols to: " + str(outfile)
with open(str(outfile), "w") as f:
    json.dump(symbols, f)
