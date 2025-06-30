from base64 import b64decode

from ghidra.program.model.data import *
from ghidra.program.model.symbol import *


def main():
    # addr_factory = currentProgram.getAddressFactory()
    memory = currentProgram.getMemory()
    selection = currentSelection
    if selection is None:
        print("No selection found")
        return
    start = selection.getMinAddress()
    end = selection.getMaxAddress()

    size = end.subtract(start)
    new_label = True
    bs = bytearray()
    offset = 0
    for i in range(size + 1):
        if new_label:
            offset = i
            bs = bytearray()
            new_label = False
        b = memory.getByte(start.add(i))
        bs.append(b)

        if b == 0:
            lbl = b64decode(bs)
            print(lbl)
            createLabel(start.add(offset), "g_s_" + lbl.replace(" ", "_"), True)
            new_label = True


main()
