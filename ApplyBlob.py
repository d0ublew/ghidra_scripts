# -*- coding: utf-8 -*-
# Ghidra script: patch a contiguous byte blob from an external hex file at a
# given start address — single setBytes call (fast even for KB-sized blobs).
#
# Edit HEX_FILE and START. Run from Script Manager.
#
#@category Patching
#@menupath Tools.Patching.Apply Blob
#@runtime Jython

import jarray
from ghidra.app.util.exporter import BinaryExporter
from java.io import File

# ---- EDIT THIS ----
START       = 0x100664ff0
HEX_FILE    = "/tmp/hexstr.txt"        # one big contiguous hex string (whitespace OK)
EXPORT_PATH = None                       # e.g. "/tmp/patched.bin" or None
# -------------------

# load + normalize hex
with open(HEX_FILE) as f:
    raw = f.read()
hex_str = "".join(raw.split()).lower()
if len(hex_str) % 2:
    raise ValueError("hex length not even: %d" % len(hex_str))
n = len(hex_str) // 2
print("[*] loaded %d hex chars from %s -> %d bytes" % (len(hex_str), HEX_FILE, n))

# build java byte[]
buf = jarray.zeros(n, 'b')
for i in range(n):
    v = int(hex_str[2*i:2*i+2], 16)
    if v > 127: v -= 256
    buf[i] = v

addr = toAddr(START)
end  = addr.add(n - 1)
mem  = currentProgram.getMemory()

# capture original bytes briefly for log (first + last word)
def hex4(addr):
    return "".join("%02X" % (b & 0xFF) for b in getBytes(addr, 4))

orig_first = hex4(addr)
orig_last  = hex4(end.subtract(3))

print("[*] clearListing %s - %s" % (addr, end))
clearListing(addr, end)

print("[*] setBytes %d bytes @ %s" % (n, addr))
mem.setBytes(addr, buf)

print("[*] disassemble %s" % addr)
disassemble(addr)

print("[+] patched: first 4 bytes %s -> %s, last 4 bytes %s -> %s"
      % (orig_first, hex4(addr), orig_last, hex4(end.subtract(3))))

if EXPORT_PATH:
    exp = BinaryExporter()
    out = File(EXPORT_PATH)
    ok  = exp.export(out, currentProgram, None, monitor)
    print("[+] exported to %s (success=%s)" % (EXPORT_PATH, ok))
else:
    print("[i] no EXPORT_PATH; use File -> Export Program... to save")
