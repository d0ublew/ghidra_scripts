# Decrypt embedded DEX from Codemix unpacker.
# Algorithm: each byte XOR 0xFF (bitwise NOT).
# Reads innerDex blob, decrypts, saves to file.
#
# @author Crowe Cybersecurity
# @category Analysis.Crypto
# @keybinding
# @menupath Analysis.Decrypt Codemix DEX
# @toolbar

import jarray
import os

INNER_DEX_ADDR = 0x0010c000
INNER_DEX_LEN_ADDR = 0x0010da00

def main():
    mem = currentProgram.getMemory()

    len_buf = jarray.zeros(4, "b")
    mem.getBytes(toAddr(INNER_DEX_LEN_ADDR), len_buf)
    dex_len = 0
    for i in range(4):
        dex_len |= (len_buf[i] & 0xFF) << (i * 8)

    println("[*] innerDex @ 0x{:08x}".format(INNER_DEX_ADDR))
    println("[*] innerDexLen @ 0x{:08x} = {} bytes".format(INNER_DEX_LEN_ADDR, dex_len))

    if dex_len == 0 or dex_len > 0x100000:
        println("[-] Suspicious length: {}. Aborting.".format(dex_len))
        return

    enc_buf = jarray.zeros(dex_len, "b")
    mem.getBytes(toAddr(INNER_DEX_ADDR), enc_buf)

    dec_buf = bytearray(dex_len)
    for i in range(dex_len):
        dec_buf[i] = (enc_buf[i] & 0xFF) ^ 0xFF

    magic = str(dec_buf[:4])
    println("[*] Decrypted magic: {}".format(repr(magic)))
    if not magic.startswith("dex\n"):
        println("[!] Warning: does not start with DEX magic. May need additional decryption.")

    out_path = str(askFile("Save decrypted DEX as", "Save"))

    with open(out_path, "wb") as f:
        f.write(dec_buf)

    println("[+] Saved decrypted DEX: {}".format(out_path))
    println("[+] Size: {} bytes".format(dex_len))
    println("[*] Open in jadx/bytecodeviewer/jeb to analyze.")

main()
