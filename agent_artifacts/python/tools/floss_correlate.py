# floss_correlate.py
# Purpose: correlate FLOSS JSON output with a list of data VAs (e.g., from Ghidra script)
# Usage: python3 floss_correlate.py floss_output.json data_vas.txt
#  - floss_output.json: FLOSS -j output (JSON array or object with 'strings')
#  - data_vas.txt: newline-separated addresses (hex) such as 0x140001200

import sys
import json

if len(sys.argv) < 2:
    print("Usage: floss_correlate.py <floss_json> [data_vas.txt]")
    sys.exit(1)

floss_file = sys.argv[1]
vas = set()
if len(sys.argv) > 2:
    with open(sys.argv[2], 'r') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                if line.lower().startswith('0x'):
                    va = int(line, 16)
                else:
                    va = int(line, 16)
                vas.add(va)
            except:
                pass

with open(floss_file, 'r') as f:
    j = json.load(f)

# FLOSS  output formats vary. Handle a few common shapes.
strings = []
if isinstance(j, dict):
    if 'strings' in j:
        strings = j['strings']
    else:
        # maybe it's single list
        strings = j.get('decoded_strings') or j.get('results') or []
elif isinstance(j, list):
    strings = j

print('Found %d string entries in FLOSS output' % len(strings))

for s in strings:
    # try to find the decoded string and origin VA
    decoded = None
    origin = None
    if isinstance(s, dict):
        decoded = s.get('decoded') or s.get('string') or s.get('value') or s.get('decoded_string') or s.get('content')
        origin = s.get('va') or s.get('offset') or s.get('address') or s.get('origin_va')
    else:
        decoded = s
    if decoded is None:
        continue
    try:
        if origin is not None:
            if isinstance(origin, str) and origin.lower().startswith('0x'):
                origin_va = int(origin, 16)
            else:
                origin_va = int(origin)
        else:
            origin_va = None
    except:
        origin_va = None
    referenced = False
    if origin_va is not None and origin_va in vas:
        referenced = True
    print('STRING: %s' % repr(decoded))
    print('  origin_va: %s   referenced_by_candidate_data: %s' % (hex(origin_va) if origin_va else 'N/A', referenced))

print('Done')
