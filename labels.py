from ghidra.program.model.symbol import *
from ghidra.program.model.data import *

addr_factory = currentProgram.getAddressFactory()

f = askFile("Give me a file to open", "Choose")
for line in file(f.absolutePath):
    addr, lbl = line.strip().split(",")
    if not addr.startswith("0x"):
        addr = hex(int(addr))
    addr = addr_factory.getAddress(addr)
    print("Creating label " + lbl + " @ " + str(addr))
    createLabel(addr, lbl, True)
