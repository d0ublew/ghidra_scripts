from ghidra.program.model.symbol import *
from ghidra.program.model.data import *

xref_mgr = currentProgram.getReferenceManager()

xref_iter = xref_mgr.getReferencesTo(currentAddress)

for xref in xref_iter:
    addr = (xref.getFromAddress().subtract(0xc))
    fn = getFunctionAt(addr)
    # fn.setInline(False)
    char_pointer2 = getInstructionAt(addr.add(0x4)).getAddress(1)
    try:
        char_pointer = getDataAt(char_pointer2).getValue()
        data = getDataAt(char_pointer)
        fn_name = "msgSend_" + (data.getValue())
        # print("Renaming function @ " + str(addr) + " => " + fn_name);
        fn.setName(fn_name, ghidra.program.model.symbol.SourceType.DEFAULT)
    except:
        print("Failed to rename function @ " + str(addr))
