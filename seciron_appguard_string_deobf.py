from ghidra.program.model.data import *
from ghidra.program.model.symbol import *


def wide_deobf(bs):
    out = bytearray()
    for i in range(0, len(bs), 2):
        if bs[i] == 0:
            break
        out.append(bs[i] + ~(i + (i // 3) * -3))
    return bytes(out).decode()


def deobf(bs):
    out = bytearray()
    for i in range(0, len(bs)):
        if bs[i] == 0:
            break
        out.append(bs[i] + ~(i + (i // 3) * -3))
    return bytes(out).decode()


# def main():
#     addr_factory = currentProgram.getAddressFactory()
#     memory = currentProgram.getMemory()
#     selection = currentSelection
#     if selection is None:
#         print("No selection found")
#         return
#     start = selection.getMinAddress()
#     end = selection.getMaxAddress()
#
#     size = end.subtract(start)
#     bs = bytearray()
#     for i in range(size):
#         b = memory.getByte(start.add(i))
#         bs.append(b)
#     if len(bs) >= 2 and bs[1] == 0:
#         s = wide_deobf(bs)
#     else:
#         s = deobf(bs)
#     s = s.replace(" ", "_")
#     createLabel(start, "g_s_" + s, True)


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
    wide_flag = False
    bs = bytearray()
    offset = 0
    for i in range(size + 1):
        if new_label:
            offset = i
            bs = bytearray()
            new_label = False
            wide_flag = False
        b = memory.getByte(start.add(i))
        bs.append(b)

        if len(bs) >= 2:
            if bs[1] == 0:
                wide_flag = True
            if b == 0:
                if wide_flag and (i - offset) % 2 == 0:
                    s = wide_deobf(bs)
                    print(s)
                    print("wide_deobf g_s_" + s + " @ " + str(start.add(offset)))
                    createLabel(start.add(offset), "g_s_" + s.replace(" ", "_"), True)
                    new_label = True
                elif not wide_flag:
                    s = deobf(bs)
                    print(s)
                    print("deobf g_s_" + s + " @ " + str(start.add(offset)))
                    createLabel(start.add(offset), "g_s_" + s.replace(" ", "_"), True)
                    new_label = True


main()
