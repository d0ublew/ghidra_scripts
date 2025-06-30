from ghidra.program.model.data import *
from ghidra.program.model.symbol import *

xref_mgr = currentProgram.getReferenceManager()

xref_iter = xref_mgr.getReferencesTo(currentAddress)
image_base = currentProgram.getImageBase()

eps = []
for xref in xref_iter:
    addr = xref.getFromAddress()
    print(addr)
    eps.append(addr.subtract(image_base))

hook = """\
const offsets = [{eps}];
for (const o of offsets) {{
    Interceptor.attach(lib_base.add(o), function() {{
        console.log("[*] " + o.toString(16) + " in: " + this.context.x0);
    }});
    // Interceptor.attach(lib_base.add(o).add(0x4), function() {{
    //     console.log("[*] " + o.toString(16) + " out: " + this.context.x0);
    // }});
}}\
        """.format(eps=", ".join(list(map(lambda x: hex(int(x)), sorted(eps)))))
print(hook)
