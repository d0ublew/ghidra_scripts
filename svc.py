from ghidra.program.model.symbol import *
from ghidra.program.model.data import *

xref_mgr = currentProgram.getReferenceManager()
addr_factory = currentProgram.getAddressFactory()
base = addr_factory.getAddress("0x01000000")
xref_mgr.addMemoryReference(currentAddress, base, RefType.CALLOTHER_OVERRIDE_CALL, SourceType.USER_DEFINED, 0)
