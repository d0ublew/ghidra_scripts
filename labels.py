from ghidra.program.model.data import *
from ghidra.program.model.symbol import *

addr_factory = currentProgram.getAddressFactory()

f = askFile("Give me a file to open", "Choose")
for line in file(f.absolutePath):
    addr, sep, lbl = line.strip().partition(",")
    if not addr.startswith("0x"):
        addr = hex(int(addr))
    addr = addr_factory.getAddress(addr)
    print("Creating label " + lbl + " @ " + str(addr))
    lbl = lbl[:256]
    # createLabel(addr.add(0x100000), lbl, True)
    createLabel(addr, lbl, True)
