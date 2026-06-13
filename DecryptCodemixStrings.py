# Decrypt XOR-encrypted strings in Codemix unpacker native library.
# Algorithm: plaintext[i] = ciphertext[i] ^ key[i % key_modulo]
# Each decN function uses a different key_modulo value.
# Renames encrypted data labels to s_<decrypted_value> and prints to console.
#
# @author Crowe Cybersecurity
# @category Analysis.Crypto
# @keybinding
# @menupath Analysis.Decrypt Codemix Strings
# @toolbar

from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.pcode import PcodeOp
import jarray

KEY_MODULO = {
    "dec0": 10,
    "dec2": 0x11,
    "dec3": 0x11,
    "dec4": 0x10,
    "dec5": 0x0e,
    "dec6": 0x11,
    "dec7": 0x0b,
    "dec8": 10,
    "dec9": 0x10,
    "dec10": 0x13,
    "dec11": 0x0b,
    "dec12": 0x11,
    "dec13": 0x0b,
    "dec14": 0x12,
}


def read_bytes_at(address, length):
    """Read raw bytes from program memory."""
    mem = currentProgram.getMemory()
    buf = jarray.zeros(length, "b")
    mem.getBytes(address, buf)
    return [b & 0xFF for b in buf]


def resolve_addr(vn, depth=0):
    """Walk varnode def-chain to resolve a RAM address."""
    if vn is None or depth > 12:
        return None
    if vn.isConstant():
        return toAddr(vn.getOffset())
    if vn.isAddress():
        return vn.getAddress()
    defOp = vn.getDef()
    if defOp is None:
        return None
    opc = defOp.getOpcode()
    if opc in (PcodeOp.COPY, PcodeOp.CAST):
        return resolve_addr(defOp.getInput(0), depth + 1)
    if opc in (PcodeOp.PTRSUB, PcodeOp.INT_ADD):
        base = resolve_addr(defOp.getInput(0), depth + 1)
        off_vn = defOp.getInput(1)
        if base is not None and off_vn.isConstant():
            return base.add(off_vn.getOffset())
    if opc == PcodeOp.MULTIEQUAL:
        return resolve_addr(defOp.getInput(0), depth + 1)
    return None


def resolve_int(vn, depth=0):
    """Walk varnode def-chain to resolve a constant integer."""
    if vn is None or depth > 12:
        return None
    if vn.isConstant():
        return int(vn.getOffset())
    defOp = vn.getDef()
    if defOp is None:
        return None
    opc = defOp.getOpcode()
    if opc in (PcodeOp.COPY, PcodeOp.CAST, PcodeOp.INT_ZEXT, PcodeOp.INT_SEXT):
        return resolve_int(defOp.getInput(0), depth + 1)
    return None


def xor_decrypt(data, key, length, mod):
    """XOR decrypt with rolling key."""
    return "".join(chr(data[i] ^ key[i % mod]) for i in range(length))


def rename_data_label(addr, plaintext):
    """Rename data label at addr to s_<decrypted_value>."""
    from ghidra.program.model.symbol import SourceType
    label = "s_" + plaintext.replace(" ", "_")
    st = currentProgram.getSymbolTable()
    existing = getSymbolAt(addr)
    if existing and not existing.isDynamic():
        existing.setName(label, SourceType.USER_DEFINED)
    else:
        st.createLabel(addr, label, SourceType.USER_DEFINED)


def main():
    decompiler = DecompInterface()
    decompiler.openProgram(currentProgram)

    fm = currentProgram.getFunctionManager()
    decompile_cache = {}
    total = 0
    results = []

    println("[*] Codemix String Decryptor")
    println("[*] Scanning {} dec functions...\n".format(len(KEY_MODULO)))

    for dec_name, mod in sorted(KEY_MODULO.items(), key=lambda x: x[0]):
        funcs = list(getGlobalFunctions(dec_name))
        if not funcs:
            println("[-] {} not found, skipping".format(dec_name))
            continue

        dec_entry = funcs[0].getEntryPoint()

        for ref in getReferencesTo(dec_entry):
            if not ref.getReferenceType().isCall():
                continue

            call_addr = ref.getFromAddress()
            caller = fm.getFunctionContaining(call_addr)
            if caller is None:
                continue

            caller_key = caller.getEntryPoint().toString()
            if caller_key not in decompile_cache:
                res = decompiler.decompileFunction(caller, 60, monitor)
                if res.decompileCompleted() and res.getHighFunction():
                    decompile_cache[caller_key] = res.getHighFunction()
                else:
                    println("[-] Decompile failed: {}".format(caller.getName()))
                    continue

            hfunc = decompile_cache[caller_key]

            ops_iter = hfunc.getPcodeOps()
            while ops_iter.hasNext():
                op = ops_iter.next()
                if op.getOpcode() != PcodeOp.CALL:
                    continue
                target = op.getInput(0)
                if target is None or not target.getAddress().equals(dec_entry):
                    continue
                if op.getNumInputs() < 4:
                    println(
                        "[-] {} call has {} inputs, expected 4".format(
                            dec_name, op.getNumInputs()
                        )
                    )
                    continue

                data_addr = resolve_addr(op.getInput(1))
                length = resolve_int(op.getInput(2))
                key_addr = resolve_addr(op.getInput(3))

                if data_addr is None or length is None or key_addr is None:
                    println(
                        "[-] Unresolved: {}(data={}, len={}, key={}) in {}".format(
                            dec_name, data_addr, length, key_addr, caller.getName()
                        )
                    )
                    continue

                try:
                    data_bytes = read_bytes_at(data_addr, length)
                    key_bytes = read_bytes_at(key_addr, max(mod, length))
                    plaintext = xor_decrypt(data_bytes, key_bytes, length, mod)

                    old_sym = getSymbolAt(data_addr)
                    old_name = old_sym.getName() if old_sym else "0x{:x}".format(
                        data_addr.getOffset()
                    )
                    rename_data_label(data_addr, plaintext)
                    new_sym = getSymbolAt(data_addr)
                    sym_name = new_sym.getName() if new_sym else old_name

                    println(
                        '[+] {}({}, len={}, key={}) => "{}"'.format(
                            dec_name, sym_name, length, key_addr, plaintext
                        )
                    )
                    results.append((dec_name, sym_name, plaintext, caller.getName()))
                    total += 1

                except Exception as e:
                    println(
                        "[-] Decrypt error: {} @ {}: {}".format(dec_name, call_addr, e)
                    )

    decompiler.dispose()

    println("\n" + "=" * 60)
    println("[*] SUMMARY: Decrypted {} strings".format(total))
    println("=" * 60)
    for dec_name, sym, plain, caller in results:
        println('  {} in {}: "{}"'.format(sym, caller, plain))
    println("=" * 60)


main()
