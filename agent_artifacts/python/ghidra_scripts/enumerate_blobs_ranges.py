# Ghidra script: enumerate contiguous data items in specified ranges and compute printable fraction + entropy + xrefs
# Save this script to Ghidra's script manager and run against the loaded program.
# Outputs to console and writes CSV to user-specified file in current working directory.

from ghidra.program.model.address import Address
from ghidra.program.model.listing import Function
from java.io import FileWriter, BufferedWriter
import math

# CONFIG: ranges to scan (inclusive start, exclusive end)
RANGES = [
    (0x140004000, 0x140004000 + 0xE00),  # .rdata as requested
    (0x140003000, 0x140003000 + 0x200)   # .data (0x1ff inclusive -> +0x200 exclusive)
]

# Optional: list of decode-loop function start addresses (hex) from prior work item 2.
# If known, set DECODE_FUNCS = [0x14000abcd, ...]. If left empty, script will still list function callers for xrefs.
DECODE_FUNCS = []
DECODE_FUNC_ADDRS = [toAddr(x) for x in DECODE_FUNCS]

OUTFILE = "ghidra_blob_enumeration.csv"

listing = currentProgram.getListing()
refmgr = currentProgram.getReferenceManager()
mem = currentProgram.getMemory()

def shannon_entropy(bytearr):
    if not bytearr:
        return 0.0
    freq = [0]*256
    for b in bytearr:
        freq[b & 0xff] += 1
    ent = 0.0
    length = float(len(bytearr))
    for f in freq:
        if f == 0:
            continue
        p = f / length
        ent -= p * math.log(p, 2)
    return ent

def printable_fraction(bytearr):
    if not bytearr:
        return 0.0
    printable = 0
    for b in bytearr:
        if 0x20 <= (b & 0xff) <= 0x7e:
            printable += 1
    return float(printable) / float(len(bytearr))

# Helper to gather unique xrefs to any address inside range

def gather_xrefs(range_start_addr, size):
    xrefs = {}
    for off in range(size):
        a = toAddr(range_start_addr.getOffset() + off)
        refs = refmgr.getReferencesTo(a)
        for r in refs:
            from_addr = r.getFromAddress()
            if from_addr not in xrefs:
                func = listing.getFunctionContaining(from_addr)
                func_entry = func.getEntryPoint() if func else None
                xrefs[from_addr] = {'from': from_addr, 'function': func_entry}
    return xrefs

# Main
results = []
for (s,e) in RANGES:
    start = toAddr(s)
    end = toAddr(e-1)
    addr = start
    while addr.compareTo(end) <= 0:
        data = listing.getDefinedDataAt(addr)
        if data is None:
            # advance by one byte
            addr = addr.add(1)
            continue
        length = data.getLength()
        if length > 32:
            # read bytes
            try:
                bytearr = getBytes(addr, length)
            except Exception as ex:
                print("Failed to read bytes at %s len=%d: %s" % (addr, length, ex))
                addr = addr.add(length)
                continue
            # compute metrics
            ent = shannon_entropy(bytearr)
            printable = printable_fraction(bytearr)
            # gather xrefs
            xref_map = gather_xrefs(addr, length)
            xref_list = []
            for fa, info in xref_map.items():
                func_entry = info['function']
                xref_list.append((str(info['from']), str(func_entry) if func_entry else None))
            results.append({
                'start': str(addr),
                'length': length,
                'printable_fraction': printable,
                'entropy': ent,
                'xrefs': xref_list
            })
            # advance
            addr = addr.add(length)
        else:
            addr = addr.add(data.getLength())

# Write CSV
try:
    fw = BufferedWriter(FileWriter(OUTFILE))
    fw.write('start,length,printable_fraction,entropy,xref_count,xrefs\n')
    for r in results:
        xref_count = len(r['xrefs'])
        xref_str = ';'.join([('%s|%s' % (x[0], x[1] if x[1] else 'NONE')) for x in r['xrefs']])
        line = '%s,%d,%.4f,%.4f,%d,"%s"\n' % (r['start'], r['length'], r['printable_fraction'], r['entropy'], xref_count, xref_str)
        fw.write(line)
    fw.close()
    print('Wrote %d blob records to %s' % (len(results), OUTFILE))
except Exception as ex:
    print('Failed to write CSV: %s' % ex)

# Also print summary to console
for r in results:
    print('BLOB %s len=%d printable=%.4f entropy=%.4f xrefs=%d' % (r['start'], r['length'], r['printable_fraction'], r['entropy'], len(r['xrefs'])))
    for x in r['xrefs']:
        print('  xref from %s in func %s' % (x[0], x[1]))

if not results:
    print('No data items >32 bytes found in configured ranges.')
