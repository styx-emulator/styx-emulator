# BSD 2-Clause License
#
# Copyright (c) 2024, Styx Emulator Project
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this
#    list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
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
