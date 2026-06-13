# BulkRename.py

renames = {
    "FUN_0019b1d8": "__emutls_get_address",
    "FUN_0019b3dc": "__emutls_init_key",
    "FUN_0019b418": "__emutls_tls_destructor",
    "DAT_001a6e74": "__emutls_pthread_key",
    "DAT_001a6e78": "__emutls_once",
    "DAT_001a6e80": "__emutls_num_objects",
    "DAT_001a6e88": "__emutls_mutex",
    "DAT_001a6e70": "__emutls_initialized",
}

from ghidra.program.model.symbol import SourceType

st = currentProgram.getSymbolTable()

for old_name, new_name in renames.items():
    symbols = st.getSymbols(old_name)

    for sym in symbols:
        sym.setName(new_name, SourceType.USER_DEFINED)
        print("Renamed", old_name, "->", new_name)
