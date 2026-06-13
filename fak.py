from ghidra.program.model.data import *
from ghidra.program.model.symbol import *

fn_mgr = currentProgram.getFunctionManager()
addr_factory = currentProgram.getAddressFactory()
addr = addr_factory.getAddress("0x001a00a8")
print(addr)
createFunction(addr, "fn_test2")
fn = fn_mgr.getFunctionAt(addr)
fn.setName("fn_test2", SourceType.USER_DEFINED)
