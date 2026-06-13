from ghidra.program.model.data import *
from ghidra.program.model.symbol import *

addr_factory = currentProgram.getAddressFactory()
fn_mgr = currentProgram.getFunctionManager()

f = askFile("Give me a file to open", "Choose")
for line in file(f.absolutePath):
    tmp = line.strip().split(" ")
    addr = addr_factory.getAddress(tmp[0])
    fn_name = tmp[-1]
    print("Creating function " + fn_name + " @ " + tmp[0])
    createFunction(addr, fn_name)
    fn = fn_mgr.getFunctionAt(addr)
    fn.setName(fn_name, SourceType.USER_DEFINED)
