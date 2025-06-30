from ghidra.program.model.data import *
from ghidra.program.model.symbol import *

xref_mgr = currentProgram.getReferenceManager()

xref_iter = xref_mgr.getReferencesTo(currentAddress)
image_base = currentProgram.getImageBase()

for xref in xref_iter:
    addr = xref.getFromAddress()
    fn = getFunctionContaining(addr)
    entry_point = fn.getEntryPoint()

    hook = """\
Interceptor.attach(lib_base.add({offset}), {{
    onEnter(args) {{
        this.out = args[0];
        // console.log("[*] {offset} in");
    }},
    onLeave(retval) {{
        console.log("[*] {offset} vsprintf out: " + this.out.readCString());
    }},
}})\
""".format(offset=hex(int(entry_point.subtract(image_base))))
    print(hook)
