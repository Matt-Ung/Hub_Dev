# Ghidra script: find_config_decoder.py
# Purpose: locate functions referencing config/decoder-related strings, decompile them, and save pseudocode + xrefs
# Usage: run from Ghidra's Script Manager (analyze with open program first)

from ghidra.program.model.listing import CodeUnit
from ghidra.util.task import TaskMonitor
from ghidra.app.decompiler import DecompInterface
from ghidra.app.decompiler import DecompileOptions
from java.io import FileWriter, BufferedWriter

patterns = [
    "=== Config Decoder Test ===",
    "decoded %d bytes of",
    "[warn] malformed config line at offset %d",
    "config",
    "decode"
]

out_path = "config_decoder_artifacts.txt"
fw = BufferedWriter(FileWriter(out_path))

fw.write("Config decoder artifact dump\n")
fw.write("=========================\n\n")

listing = currentProgram.getListing()
strings = listing.getDefinedData(True)

# Collect string data units that match patterns
matched_strings = []
for s in strings:
    try:
        if s.getDataType().getName() in ["string", "unicode"] or s.getDataType().getName().lower().startswith("char"):
            sval = s.getValue()
            if sval is None:
                continue
            for p in patterns:
                if p in str(sval):
                    matched_strings.append((s, str(sval)))
                    break
    except Exception:
        pass

if not matched_strings:
    fw.write("No matching strings found by patterns.\n")
    fw.close()
    print("No matching strings found. Output written to %s" % out_path)
    return

# Setup decompiler
dec = DecompInterface()
dec.openProgram(currentProgram)

for data_unit, sval in matched_strings:
    addr = data_unit.getMinAddress()
    fw.write("STRING: %s @ %s\n" % (sval, addr))
    refs = getReferencesTo(addr)
    if not refs:
        fw.write("  (no xrefs)\n\n")
        continue
    for r in refs:
        fw.write("  XREF: %s from %s\n" % (r.getFromAddress(), r.getReferenceType()))
        func = getFunctionContaining(r.getFromAddress())
        if func is None:
            fw.write("    Not inside a function\n")
            continue
        fw.write("    Function: %s @ %s\n" % (func.getName(), func.getEntryPoint()))
        # Decompile
        res = dec.decompileFunction(func, 60, TaskMonitor.DUMMY)
        if res is None or not res.decompileCompleted():
            fw.write("    Decompilation failed or timed out\n")
            continue
        pseudocode = res.getDecompiledFunction().getC()
        fw.write("    --- PSEUDOCODE START ---\n")
        fw.write(pseudocode.encode('utf-8'))
        fw.write("\n    --- PSEUDOCODE END ---\n\n")

fw.close()
print("Done. Artifacts saved to %s" % out_path)
