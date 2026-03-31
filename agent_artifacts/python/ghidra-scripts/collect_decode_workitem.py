# Ghidra script: collect_decode_workitem.py
# Purpose: Collect evidence for work_item 1
# Output: JSON printed to stdout with sections: virtualprotect_xrefs, entry_callgraph_loops, main_callgraph_loops, data_references

from ghidra.program.model.symbol import SymbolType
from ghidra.program.model.address import Address
from ghidra.program.model.listing import CodeUnit
from ghidra.util.task import ConsoleTaskMonitor
import json

monitor = ConsoleTaskMonitor()

def toAddr(val):
    return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(val)

result = {
    'virtualprotect_xrefs': [],
    'entry_callgraph_loops': [],
    'main_callgraph_loops': [],
    'rdata_data_references': [],
    'data_data_references': []
}

# 1) Find VirtualProtect symbol(s)
sym_table = currentProgram.getSymbolTable()
vp_symbols = list(sym_table.getSymbols("VirtualProtect"))

if not vp_symbols:
    # try with case-insensitive search by scanning externals
    for sym in sym_table.getSymbols(None):
        if sym.getName() and sym.getName().lower() == 'virtualprotect':
            vp_symbols.append(sym)

from ghidra.program.model.symbol import RefType
from ghidra.program.model.symbol import SourceType
from ghidra.program.model.symbol import Symbol
from ghidra.program.model.listing import Listing
from ghidra.program.model.symbol import Reference

ref_manager = currentProgram.getReferenceManager()
listing = currentProgram.getListing()

for sym in vp_symbols:
    sym_addr = sym.getAddress()
    refs = ref_manager.getReferencesTo(sym_addr)
    for r in refs:
        from_addr = r.getFromAddress()
        func = listing.getFunctionContaining(from_addr)
        func_start = func.getEntryPoint() if func else None
        entry_hex = hex(func_start.getOffset()) if func_start else None
        instr_offset = hex(from_addr.getOffset())
        result['virtualprotect_xrefs'].append({
            'symbol_name': sym.getName(),
            'symbol_address': str(sym_addr),
            'from_address': str(from_addr),
            'containing_function_start': str(func_start) if func_start else None,
            'containing_function_start_offset_hex': entry_hex,
            'instruction_offset_hex': instr_offset
        })

# Helper: determine if a function contains a backward branch (simple loop heuristic)
def function_contains_loop(func):
    if not func:
        return False, None
    body = func.getBody()
    addr_set_iter = body.getAddresses(True)
    addr_iter = addr_set_iter
    # iterate instructions
    inst = listing.getInstructionAt(func.getEntryPoint())
    while inst and body.contains(inst.getAddress()):
        refs_from = inst.getReferencesFrom()
        for ref in refs_from:
            try:
                to = ref.getToAddress()
            except Exception:
                continue
            # consider flow references with to < current => back edge
            if ref.getReferenceType().isFlow() and to < inst.getAddress():
                return True, (str(inst.getAddress()), str(to))
        inst = inst.getNext()
    return False, None

# 2) Call graph from specific addresses (entry and main)
from collections import deque

def collect_callgraph_loops(start_addr_hex):
    start_addr = toAddr(int(start_addr_hex,16))
    start_func = listing.getFunctionContaining(start_addr)
    if not start_func:
        # maybe function starts at that address
        start_func = listing.getFunctionAt(start_addr)
    if not start_func:
        return []
    results = []
    visited = set()
    q = deque()
    q.append((start_func,0))
    max_nodes = 200
    while q and len(visited) < max_nodes:
        func, depth = q.popleft()
        func_entry = func.getEntryPoint()
        func_key = str(func_entry)
        if func_key in visited:
            continue
        visited.add(func_key)
        has_loop, loop_info = function_contains_loop(func)
        if has_loop:
            # find loop boundaries approximately: collect first backward branch found
            results.append({
                'function_start': str(func_entry),
                'function_start_offset_hex': hex(func_entry.getOffset()),
                'loop_detected': True,
                'loop_sample': loop_info
            })
        # find called functions
        inst = listing.getInstructionAt(func.getEntryPoint())
        while inst and func.getBody().contains(inst.getAddress()):
            refs_from = inst.getReferencesFrom()
            for ref in refs_from:
                if ref.getReferenceType().isCall():
                    callee_addr = ref.getToAddress()
                    callee_func = listing.getFunctionContaining(callee_addr)
                    if callee_func:
                        q.append((callee_func, depth+1))
            inst = inst.getNext()
    return results

# Use provided addresses (hex) - these are canonical from the planner
entry_point_hex = '0x140001400'
main_hex = '0x140001792'

result['entry_callgraph_loops'] = collect_callgraph_loops(entry_point_hex)
result['main_callgraph_loops'] = collect_callgraph_loops(main_hex)

# 3) References to addresses inside .rdata and .data
mem = currentProgram.getMemory()
blocks = {b.getName(): b for b in mem.getBlocks()}

rdata_block = None
data_block = None
for name, b in blocks.items():
    if name.lower().startswith('.rdata'):
        rdata_block = b
    if name.lower().startswith('.data'):
        data_block = b

def gather_refs_for_block(block, out_list):
    if not block:
        return
    start = block.getStart()
    end = block.getEnd()
    addr = start
    while addr <= end:
        data = listing.getDefinedDataAt(addr)
        if data:
            refs = ref_manager.getReferencesTo(addr)
            for r in refs:
                from_addr = r.getFromAddress()
                func = listing.getFunctionContaining(from_addr)
                out_list.append({
                    'referenced_data_address': str(addr),
                    'from_address': str(from_addr),
                    'containing_function_start': str(func.getEntryPoint()) if func else None
                })
            addr = addr.add(data.getLength())
        else:
            addr = addr.add(1)

gather_refs_for_block(rdata_block, result['rdata_data_references'])
gather_refs_for_block(data_block, result['data_data_references'])

print(json.dumps(result, indent=2))
