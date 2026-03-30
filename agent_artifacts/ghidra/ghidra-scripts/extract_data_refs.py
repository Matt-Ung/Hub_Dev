# Ghidra Python script: extract_data_refs.py
# Purpose: For a set of candidate functions (or auto-detected decoder-like functions),
# enumerate data references into .rdata/.data, extract raw bytes (up to 512 bytes),
# and attempt to record nearby immediate constants used as lengths.
# Usage: run from Ghidra (Script Manager) on an opened program. Save output to console
# or modify to write to a file.

from ghidra.program.model.listing import CodeUnit
from ghidra.program.model.symbol import RefType
from ghidra.program.flatapi import FlatProgramAPI
from ghidra.program.model.address import Address
from ghidra.util.task import ConsoleTaskMonitor

api = FlatProgramAPI(currentProgram)
monitor = ConsoleTaskMonitor()

# Configuration
MAX_BLOB_BYTES = 512
BACKSCAN_INSTRUCTIONS = 8
FUNC_NAME_KEYWORDS = ["decode", "decrypt", "parse", "config", "deobf"]

# Optional: supply addresses (as strings) of candidate functions here.
# Example: candidate_addrs = ["0x140001200", "0x1400013f0"]
candidate_addrs = []

out_lines = []

def addr_to_hex(a):
    return "0x%X" % a.getOffset()


def read_blob(addr, max_bytes=MAX_BLOB_BYTES):
    # read up to max_bytes or until 0x00
    b = bytearray()
    try:
        for i in range(max_bytes):
            val = api.getByte(addr.add(i))
            b.append(val & 0xFF)
            if val == 0:
                break
    except Exception as e:
        pass
    return bytes(b)


def find_nearby_immediates(instr):
    # scan up to BACKSCAN_INSTRUCTIONS previous instructions for Scalar operands
    imms = []
    count = 0
    cur = instr
    while cur is not None and count < BACKSCAN_INSTRUCTIONS:
        for opIndex in range(cur.getNumOperands()):
            for op in cur.getOpObjects(opIndex):
                try:
                    from ghidra.program.model.scalar import Scalar
                    if isinstance(op, Scalar):
                        imms.append((addr_to_hex(cur.getAddress()), op.getValue()))
                except Exception:
                    pass
        cur = cur.getPrevious()
        count += 1
    return imms


def get_block_file_offset_for_addr(target):
    # Best-effort: return tuple (block_name, block_start_va_hex, block_file_offset_or_None)
    try:
        mem = currentProgram.getMemory()
        block = mem.getBlock(target)
        block_start = block.getStart()
        block_name = block.getName()
        # MemoryBlock may not expose file offset in all loaders; attempt to access
        file_offset = None
        try:
            # Some MemoryBlock instances have getStart(), getName(); file offsets may be in
            # block.getStart().toString() only. We will attempt to compute file offset using
            # the program's image base and the loader mapping if available.
            # Fallback: None
            file_offset = block.getStart().getOffset()
        except Exception:
            file_offset = None
        return (block_name, addr_to_hex(block_start), file_offset)
    except Exception:
        return (None, None, None)


# Gather candidate functions
functions = []
if candidate_addrs:
    for s in candidate_addrs:
        try:
            a = api.toAddr(int(s, 16))
            f = getFunctionContaining(a)
            if f:
                functions.append(f)
        except Exception:
            pass
else:
    # heuristic: find functions with a keyword in the name
    all_funcs = getFunctionManager().getFunctions(True)
    for f in all_funcs:
        n = f.getName().lower()
        if any(k in n for k in FUNC_NAME_KEYWORDS):
            functions.append(f)

if not functions:
    print("No candidate functions auto-detected. Provide candidate_addrs list and re-run.")

# Process each function
for f in functions:
    fout = []
    fout.append("FUNCTION %s @ %s" % (f.getName(), addr_to_hex(f.getEntryPoint())))
    # iterate instructions in function
    instrIter = api.getInstructionIterator(f.getBody(), True)
    seen_targets = set()
    while instrIter.hasNext():
        instr = instrIter.next()
        addr = instr.getAddress()
        for opIndex in range(instr.getNumOperands()):
            try:
                refs = instr.getOperandReferences(opIndex)
            except Exception:
                refs = []
            for ref in refs:
                # consider memory/data refs
                if ref.getReferenceType().isMemoryReference() or ref.getReferenceType().isData():
                    tgt = ref.getToAddress()
                    if tgt is None:
                        continue
                    if tgt in seen_targets:
                        continue
                    seen_targets.add(tgt)
                    # read blob
                    blob = read_blob(tgt, MAX_BLOB_BYTES)
                    blob_hex = blob.hex()
                    if len(blob_hex) > 512*2:
                        blob_hex = blob_hex[:512*2]
                    block_name, block_start_hex, block_file_offset = get_block_file_offset_for_addr(tgt)
                    imms = find_nearby_immediates(instr)
                    fout.append("  REF at %s -> %s (block=%s, block_start=%s, file_offset_hint=%s)" % (
                        addr_to_hex(addr), addr_to_hex(tgt), str(block_name), str(block_start_hex), str(block_file_offset)
                    ))
                    fout.append("    nearby_immediates=%s" % (str(imms)))
                    fout.append("    blob_len=%d bytes (truncated to %d)" % (len(blob), MAX_BLOB_BYTES))
                    fout.append("    blob_hex_prefix=%s" % (blob_hex))
    print('\n'.join(fout))

print("Script finished. If no functions were found, populate candidate_addrs and re-run.")
