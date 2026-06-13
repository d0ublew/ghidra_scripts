# CreateEmutlsStructs.py

from ghidra.program.model.data import *

dtm = currentProgram.getDataTypeManager()

# Category path
cat = CategoryPath("/emutls")

# --------------------------------------------------
# struct __emutls_object
# --------------------------------------------------

emutls_obj = StructureDataType(cat, "__emutls_object", 0)

emutls_obj.add(QWordDataType(), 8, "size", None)
emutls_obj.add(QWordDataType(), 8, "align", None)
emutls_obj.add(QWordDataType(), 8, "index", None)
emutls_obj.add(PointerDataType(), 8, "initializer", None)

dtm.addDataType(emutls_obj, DataTypeConflictHandler.REPLACE_HANDLER)

# --------------------------------------------------
# struct __emutls_array
# --------------------------------------------------

emutls_arr = StructureDataType(cat, "__emutls_array", 0)

emutls_arr.add(QWordDataType(), 8, "destructor_rounds", None)
emutls_arr.add(QWordDataType(), 8, "capacity", None)

# flexible array member
void_ptr = PointerDataType(VoidDataType())

emutls_arr.add(ArrayDataType(void_ptr, 1, 8), 8, "objects", None)

dtm.addDataType(emutls_arr, DataTypeConflictHandler.REPLACE_HANDLER)

print("Created emutls structs")
