# Ghidra script: enumerate_config_blobs_ghidra.py
# Purpose: enumerate static data blobs in given VA ranges, compute entropy,
# printable ASCII fraction, simple base64-score and repeating-XOR detection,
# and gather xrefs and caller function addresses. Outputs CSV to script folder.

from __future__ import print_function
import math
import csv
import sys
from ghidra.program.model.address import Address
from ghidra.program.model.symbol import RefType

# --- CONFIG ---
IMAGE_BASE = 0x140000000
RANGES = [
    (0x140003000, 0x1400031ff, '.data'),
    (0x140004000, 0x140004e00, '.rdata'),
]
MIN_LEN = 33
OUTPUT_CSV = "config_blob_candidates.csv"
DECODE_FUNCS = []  # optionally populate with VA ints of known decode loop funcs
# --- END CONFIG ---

# helpers
def shannon_entropy(byte_arr):
    if not byte_arr:
        return 0.0
    freq = {}
    for b in byte_arr:
        freq[b] = freq.get(b, 0) + 1
    ent = 0.0
    length = float(len(byte_arr))
    for v in freq.values():
        p = v / length
        ent -= p * math.log(p, 2)
    return ent

def printable_fraction(byte_arr):
    if not byte_arr:
        return 0.0
    printable = 0
    for b in byte_arr:
        if 0x20 <= b <= 0x7e or b in (0x09, 0x0a, 0x0d):
            printable += 1
    return printable / float(len(byte_arr))

BASE64_CHARS = set(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")

def base64_score(byte_arr):
    if not byte_arr:
        return 0.0
    good = sum(1 for b in byte_arr if b in BASE64_CHARS)
    return good / float(len(byte_arr))

# Try small repeating XOR keys and return best keysize and printable fraction after XOR
def best_repeating_xor(byte_arr, max_key=8):
    best = (0, 0.0)
    for k in range(1, min(max_key, len(byte_arr)) + 1):
        # attempt to recover key by frequency (single-byte per position)
        key = []
        for pos in range(k):
            # pick byte that maximizes ASCII printable result for this column
            col = bytearray(byte_arr[pos::k])
            best_b = None
            best_frac = -1.0
            for candidate in range(0, 256):
                xored = bytearray([c ^ candidate for c in col])
                frac = printable_fraction(xored)
                if frac > best_frac:
                    best_frac = frac
                    best_b = candidate
            key.append(best_b)
        # apply key
        xored_all = bytearray((byte_arr[i] ^ key[i % k]) for i in range(len(byte_arr)))
        frac_all = printable_fraction(xored_all)
        if frac_all > best[1]:
            best = (k, frac_all)
    return best


def gather_xrefs(addr, length):
    # returns list of (fromAddr, fromFunc) tuples
    xrefs = []
    try:
        target = toAddr(addr)
        refs = getReferencesTo(target)
        for r in refs:
            fromAddr = r.getFromAddress()
            func = getFunctionContaining(fromAddr)
            func_addr = func.getEntryPoint() if func else None
            xrefs.append((str(fromAddr), str(func_addr) if func_addr else None, str(r.getReferenceType())))
    except Exception as e:
        print("gather_xrefs error:", e)
    return xrefs

# Main
out = []
for (start, end, section_name) in RANGES:
    a = toAddr(start)
    end_a = toAddr(end)
    addr = a
    while addr.compareTo(end_a) < 0:
        data = getDataAt(addr)
        if data is None:
            addr = addr.add(1)
            continue
        try:
            length = data.getLength()
        except Exception:
            # fallback: treat as 1 and continue
            length = 1
        if length >= MIN_LEN:
            try:
                ba = getBytes(addr, length)
            except Exception:
                # try memory read
                mem = currentProgram.getMemory()
                b = bytearray(length)
                mem.getBytes(addr, b)
                ba = bytes(b)
            if isinstance(ba, bytes):
                byte_arr = bytearray(ba)
            else:
                byte_arr = bytearray(ba)
            ent = shannon_entropy(byte_arr)
            pfrac = printable_fraction(byte_arr)
            b64 = base64_score(byte_arr)
            xor_keysize, xor_frac = best_repeating_xor(byte_arr, max_key=8)
            xrefs = gather_xrefs(addr.getOffset(), length)
            # check if any xref comes from decode funcs
            xref_from_decode = False
            xref_from_decode_addrs = []
            for xr in xrefs:
                from_func = xr[1]
                if from_func and int(from_func, 16) in DECODE_FUNCS:
                    xref_from_decode = True
                    xref_from_decode_addrs.append(from_func)
            out.append({
                'address': str(addr),
                'section': section_name,
                'length': length,
                'entropy': round(ent, 4),
                'printable_frac': round(pfrac, 4),
                'base64_score': round(b64, 4),
                'best_xor_keysize': xor_keysize,
                'xor_printable_frac': round(xor_frac, 4),
                'num_xrefs': len(xrefs),
                'xrefs': "|".join(["%s(%s,%s)" % (a,b,c) for (a,b,c) in xrefs]),
                'xref_from_decode': xref_from_decode,
                'xref_from_decode_addrs': ";".join(xref_from_decode_addrs)
            })
        addr = addr.add(max(1, length))

# write CSV
script_dir = getScriptDirectory()
out_path = os.path.join(script_dir, OUTPUT_CSV)
with open(out_path, 'w') as csvfile:
    writer = csv.DictWriter(csvfile, fieldnames=['address','section','length','entropy','printable_frac','base64_score','best_xor_keysize','xor_printable_frac','num_xrefs','xrefs','xref_from_decode','xref_from_decode_addrs'])
    writer.writeheader()
    for row in out:
        writer.writerow(row)

print('Wrote CSV to', out_path)
