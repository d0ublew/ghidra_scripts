from ghidra.program.model.address import AddressFormatException
from ghidra.program.model.symbol import SourceType
from ghidra.util import Msg

# Prompt user to select input file
input_file = askFile("Select function list file", "Open")

fm = currentProgram.getFunctionManager()
af = currentProgram.getAddressFactory()

with open(input_file.getAbsolutePath(), "r") as f:
    for line_num, line in enumerate(f, 1):
        line = line.strip()

        # Skip empty lines or comments
        if not line or line.startswith("#"):
            continue

        parts = line.split()
        if len(parts) < 2:
            Msg.warn(None, "Line {} malformed: {}".format(line_num, line))
            continue

        addr_str = parts[0]
        func_name = parts[1]

        try:
            addr = af.getAddress(addr_str)
            if addr is None:
                raise AddressFormatException("Invalid address")

            func = fm.getFunctionAt(addr)

            if func is None:
                # Create function
                func = fm.createFunction(func_name, addr, None, SourceType.USER_DEFINED)
                Msg.info(None, "Created function {} at {}".format(func_name, addr))
            else:
                # Rename existing function
                func.setName(func_name, SourceType.USER_DEFINED)
                Msg.info(None, "Renamed function at {} to {}".format(addr, func_name))

        except Exception as e:
            Msg.error(None, "Error on line {}: {} ({})".format(line_num, line, e))
