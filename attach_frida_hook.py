from ghidra.program.model.data import *
from ghidra.program.model.symbol import *
from java.awt import Toolkit
from java.awt.datatransfer import StringSelection

image_base = currentProgram.getImageBase()
addr = currentAddress
fn = getFunctionContaining(addr)
entry_point = fn.getEntryPoint()
fn_name = fn.getName()

hook = """\
Interceptor.attach(lib_base.add({offset}), {{
    onEnter(args) {{
        console.log("[*] {name} (@ {offset}) in");
    }},
    onLeave(retval) {{
        console.log("[*] {name} (@ {offset}) out: " + retval);
    }},
}});\
""".format(offset=hex(int(entry_point.subtract(image_base))), name=fn_name)
print(hook)


clipboard = Toolkit.getDefaultToolkit().getSystemClipboard()
clipboard.setContents(StringSelection(hook), None)
print("Copied to system clipboard")
