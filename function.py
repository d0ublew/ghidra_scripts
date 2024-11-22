from ghidra.program.model.symbol import *
from ghidra.program.model.data import *

fn_mgr = currentProgram.getFunctionManager()

for i in range(291):
    createFunction(currentAddress.add(i), "svc_{:02x}".format(i))
    # fn = fn_mgr.getFunctionAt(currentAddress.add(i))
