# Ghidra headless postScript: export a structured analysis bundle for the
# currently imported program.
#
# Usage:
#   analyzeHeadless <PROJECT_DIR> <PROJECT_NAME> \
#       -import <binary> \
#       -scriptPath <repo>/Testing \
#       -postScript ghidra_headless_export.py <output_json>

import json
import os
import sys
import time
import traceback

from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.listing import CodeUnit


def addr_str(addr):
    if addr is None:
        return ""
    try:
        return str(addr)
    except Exception:
        return ""


def safe_str(value):
    if value is None:
        return ""
    try:
        return str(value)
    except Exception:
        try:
            return unicode(value)
        except Exception:
            return repr(value)


def bool_value(value):
    try:
        return bool(value)
    except Exception:
        return False


def iter_to_list(iterator):
    items = []
    try:
        while iterator.hasNext():
            items.append(iterator.next())
    except Exception:
        try:
            for item in iterator:
                items.append(item)
        except Exception:
            pass
    return items


def symbol_name(symbol):
    if symbol is None:
        return ""
    try:
        return safe_str(symbol.getName(True))
    except Exception:
        return safe_str(symbol.getName())


def data_text(data):
    if data is None:
        return ""
    try:
        value = data.getValue()
        if value is not None:
            return safe_str(value)
    except Exception:
        pass
    try:
        value = data.getDefaultValueRepresentation()
        if value:
            return safe_str(value)
    except Exception:
        pass
    return ""


def is_probable_string(data):
    if data is None:
        return False
    try:
        data_type_name = safe_str(data.getDataType().getName()).lower()
        if "string" in data_type_name or "unicode" in data_type_name:
            return True
    except Exception:
        pass
    text = data_text(data)
    return len(text) >= 4


def collect_sections(program):
    sections = []
    memory = program.getMemory()
    for block in memory.getBlocks():
        start = addr_str(block.getStart())
        end = addr_str(block.getEnd())
        size = 0
        try:
            size = int(block.getSize())
        except Exception:
            size = 0
        sections.append(
            {
                "name": safe_str(block.getName()),
                "start": start,
                "end": end,
                "size": size,
                "read": bool_value(block.isRead()),
                "write": bool_value(block.isWrite()),
                "execute": bool_value(block.isExecute()),
                "volatile": bool_value(block.isVolatile()),
            }
        )
    return sections


def collect_imports(program):
    imports = []
    symbol_table = program.getSymbolTable()
    for symbol in iter_to_list(symbol_table.getExternalSymbols()):
        parent_name = ""
        try:
            parent = symbol.getParentNamespace()
            if parent is not None:
                parent_name = safe_str(parent.getName())
        except Exception:
            parent_name = ""
        imports.append(
            {
                "name": symbol_name(symbol),
                "address": addr_str(symbol.getAddress()),
                "namespace": parent_name,
                "symbol_type": safe_str(symbol.getSymbolType()),
            }
        )
    return imports


def collect_exports(program):
    exports = []
    symbol_table = program.getSymbolTable()
    try:
        entry_iter = symbol_table.getExternalEntryPointIterator()
        while entry_iter.hasNext():
            address = entry_iter.next()
            symbol = symbol_table.getPrimarySymbol(address)
            exports.append(
                {
                    "name": symbol_name(symbol),
                    "address": addr_str(address),
                    "symbol_type": safe_str(symbol.getSymbolType()) if symbol is not None else "",
                }
            )
    except Exception:
        pass
    return exports


def collect_strings(program):
    strings = []
    listing = program.getListing()
    iterator = listing.getDefinedData(True)
    seen = set()
    while iterator.hasNext():
        data = iterator.next()
        if not is_probable_string(data):
            continue
        address = addr_str(data.getAddress())
        text = data_text(data)
        if not text:
            continue
        key = (address, text)
        if key in seen:
            continue
        seen.add(key)
        try:
            length = int(data.getLength())
        except Exception:
            length = len(text)
        strings.append(
            {
                "address": address,
                "value": text,
                "length": length,
                "data_type": safe_str(data.getDataType().getName()),
            }
        )
    return strings


def collect_global_refs(program, import_map):
    listing = program.getListing()
    refs_to = {}
    refs_from = {}
    data_items = []
    iterator = listing.getDefinedData(True)
    while iterator.hasNext():
        data = iterator.next()
        text = data_text(data)
        if not text:
            continue
        data_items.append(
            {
                "address": addr_str(data.getAddress()),
                "label": symbol_name(program.getSymbolTable().getPrimarySymbol(data.getAddress())),
                "value": text,
                "data_type": safe_str(data.getDataType().getName()),
            }
        )

    instr_iter = listing.getInstructions(True)
    while instr_iter.hasNext():
        instruction = instr_iter.next()
        from_address = addr_str(instruction.getAddress())
        refs = instruction.getReferencesFrom()
        for ref in refs:
            to_address = addr_str(ref.getToAddress())
            ref_entry = {
                "from_address": from_address,
                "to_address": to_address,
                "ref_type": safe_str(ref.getReferenceType()),
                "operand_index": int(ref.getOperandIndex()),
            }
            data = listing.getDataAt(ref.getToAddress())
            if is_probable_string(data):
                ref_entry["string"] = data_text(data)
            imported_name = import_map.get(to_address)
            if imported_name:
                ref_entry["import_name"] = imported_name
            refs_from.setdefault(from_address, []).append(ref_entry)
            refs_to.setdefault(to_address, []).append(ref_entry)

    return refs_to, refs_from, data_items


def build_disassembly(listing, function):
    lines = []
    try:
        iterator = listing.getInstructions(function.getBody(), True)
        while iterator.hasNext():
            instruction = iterator.next()
            address = addr_str(instruction.getAddress())
            comment = listing.getComment(CodeUnit.EOL_COMMENT, instruction.getAddress())
            rendered = "%s: %s" % (address, safe_str(instruction))
            if comment:
                rendered = "%s ; %s" % (rendered, safe_str(comment))
            lines.append(rendered)
    except Exception as exc:
        lines.append("DISASSEMBLY_ERROR: %s" % safe_str(exc))
    return lines


def build_decompilation(decomp, function, warnings):
    try:
        result = decomp.decompileFunction(function, 30, monitor)
        if result is None:
            warnings.append("Decompiler returned no result for %s" % safe_str(function.getName()))
            return ""
        if not result.decompileCompleted():
            warnings.append(
                "Decompile incomplete for %s: %s"
                % (safe_str(function.getName()), safe_str(result.getErrorMessage()))
            )
        decompiled = result.getDecompiledFunction()
        if decompiled is None:
            return ""
        return safe_str(decompiled.getC())
    except Exception as exc:
        warnings.append("Decompiler exception for %s: %s" % (safe_str(function.getName()), safe_str(exc)))
        return ""


def collect_functions(program, strings_by_address, import_map, refs_to):
    listing = program.getListing()
    function_manager = program.getFunctionManager()
    decomp = DecompInterface()
    warnings = []
    failures = []
    try:
        decomp.openProgram(program)
    except Exception as exc:
        failures.append("Failed to open decompiler: %s" % safe_str(exc))

    functions = []
    call_graph = []
    function_names_by_address = {}

    function_iter = function_manager.getFunctions(True)
    all_functions = []
    while function_iter.hasNext():
        all_functions.append(function_iter.next())

    for function in all_functions:
        entry = function.getEntryPoint()
        entry_str = addr_str(entry)
        function_names_by_address[entry_str] = safe_str(function.getName())

    for function in all_functions:
        entry = function.getEntryPoint()
        entry_str = addr_str(entry)
        try:
            callers = []
            for caller in iter_to_list(function.getCallingFunctions(monitor)):
                callers.append({"name": safe_str(caller.getName()), "address": addr_str(caller.getEntryPoint())})
        except Exception:
            callers = []
        try:
            callees = []
            for callee in iter_to_list(function.getCalledFunctions(monitor)):
                callee_name = safe_str(callee.getName())
                callee_addr = addr_str(callee.getEntryPoint())
                callees.append({"name": callee_name, "address": callee_addr})
                call_graph.append(
                    {
                        "caller_name": safe_str(function.getName()),
                        "caller_address": entry_str,
                        "callee_name": callee_name,
                        "callee_address": callee_addr,
                    }
                )
        except Exception:
            callees = []

        string_refs = []
        import_refs = []
        body_instructions = listing.getInstructions(function.getBody(), True)
        seen_string_refs = set()
        seen_import_refs = set()
        while body_instructions.hasNext():
            instruction = body_instructions.next()
            for ref in instruction.getReferencesFrom():
                to_address = addr_str(ref.getToAddress())
                if to_address in strings_by_address:
                    key = (to_address, strings_by_address[to_address])
                    if key not in seen_string_refs:
                        seen_string_refs.add(key)
                        string_refs.append({"address": to_address, "value": strings_by_address[to_address]})
                imported_name = import_map.get(to_address)
                if imported_name and (to_address, imported_name) not in seen_import_refs:
                    seen_import_refs.add((to_address, imported_name))
                    import_refs.append({"address": to_address, "name": imported_name})

        try:
            signature = safe_str(function.getSignature())
        except Exception:
            signature = safe_str(function.getName())
        try:
            prototype = safe_str(function.getPrototypeString(True, True))
        except Exception:
            prototype = signature

        functions.append(
            {
                "name": safe_str(function.getName()),
                "address": entry_str,
                "entry": entry_str,
                "signature": signature,
                "prototype": prototype,
                "namespace": safe_str(function.getParentNamespace().getName()) if function.getParentNamespace() else "",
                "is_external": bool_value(function.isExternal()),
                "is_thunk": bool_value(function.isThunk()),
                "callers": callers,
                "callees": callees,
                "xref_count": len(refs_to.get(entry_str, [])),
                "string_refs": string_refs,
                "import_refs": import_refs,
                "decompilation": build_decompilation(decomp, function, warnings),
                "disassembly": build_disassembly(listing, function),
            }
        )

    try:
        decomp.dispose()
    except Exception:
        pass

    return functions, call_graph, warnings, failures


def best_effort_entry_point(program, functions):
    candidates = []
    symbol_table = program.getSymbolTable()
    for name in ["entry", "entry0", "main", "WinMain", "_start", "start"]:
        try:
            symbols = symbol_table.getSymbols(name)
            for symbol in iter_to_list(symbols):
                candidates.append({"name": symbol_name(symbol), "address": addr_str(symbol.getAddress())})
        except Exception:
            pass
    if candidates:
        return candidates[0]
    if functions:
        return {"name": functions[0].get("name"), "address": functions[0].get("address")}
    return {"name": "", "address": ""}


def determine_root_functions(functions):
    roots = []
    for function in functions:
        name = safe_str(function.get("name"))
        callers = function.get("callers") or []
        if name in ["entry", "entry0", "main", "WinMain", "_start", "start"]:
            roots.append({"name": name, "address": function.get("address")})
        elif not callers:
            roots.append({"name": name, "address": function.get("address")})
    if len(roots) > 12:
        return roots[:12]
    return roots


def main():
    if currentProgram is None:
        raise RuntimeError("No current program is loaded in Ghidra")

    args = getScriptArgs()
    if not args:
        raise RuntimeError("Output JSON path argument is required")

    output_path = os.path.abspath(args[0])
    output_dir = os.path.dirname(output_path)
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir)

    program = currentProgram
    start_ts = int(time.time())
    warnings = []
    failures = []

    sections = collect_sections(program)
    imports = collect_imports(program)
    import_map = {}
    for item in imports:
        import_map[str(item.get("address") or "")] = str(item.get("name") or "")
    exports = collect_exports(program)
    strings = collect_strings(program)
    strings_by_address = {}
    for item in strings:
        strings_by_address[str(item.get("address") or "")] = str(item.get("value") or "")
    refs_to, refs_from, data_items = collect_global_refs(program, import_map)
    functions, call_graph, function_warnings, function_failures = collect_functions(
        program,
        strings_by_address,
        import_map,
        refs_to,
    )
    warnings.extend(function_warnings)
    failures.extend(function_failures)

    function_count = len(functions)
    string_count = len(strings)
    import_count = len(imports)
    export_count = len(exports)
    xref_count = 0
    for key in refs_from:
        try:
            xref_count += len(refs_from[key])
        except Exception:
            pass

    entry_point = best_effort_entry_point(program, functions)
    root_functions = determine_root_functions(functions)

    try:
        ghidra_project_path = safe_str(program.getDomainFile().getPathname())
    except Exception:
        ghidra_project_path = ""

    payload = {
        "schema_version": 1,
        "generated_at_epoch": start_ts,
        "source": "ghidra_headless_export",
        "program": {
            "name": safe_str(program.getName()),
            "ghidraProjectPath": ghidra_project_path,
            "executablePath": safe_str(program.getExecutablePath()),
            "executableMD5": safe_str(program.getExecutableMD5()),
            "executableSHA256": safe_str(program.getExecutableSHA256()),
            "language": safe_str(program.getLanguageID().getIdAsString()),
            "compiler": safe_str(program.getCompilerSpec().getCompilerSpecID().getIdAsString()),
            "endianness": "big" if program.getLanguage().isBigEndian() else "little",
            "imageBase": addr_str(program.getImageBase()),
            "entryPoint": entry_point.get("address") or "",
        },
        "counts": {
            "functions": function_count,
            "strings": string_count,
            "imports": import_count,
            "exports": export_count,
            "references": xref_count,
            "data_items": len(data_items),
        },
        "sections": sections,
        "imports": imports,
        "exports": exports,
        "strings": strings,
        "data_items": data_items,
        "functions": functions,
        "call_graph": call_graph,
        "refs_to": refs_to,
        "refs_from": refs_from,
        "root_functions": root_functions,
        "autoAnalysisWarnings": warnings,
        "autoAnalysisFailures": failures,
    }

    handle = open(output_path, "w")
    try:
        handle.write(json.dumps(payload, indent=2, sort_keys=True))
    finally:
        handle.close()

    print("Wrote Ghidra headless export to %s" % output_path)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        printerr("Headless export failed: %s" % safe_str(exc))
        printerr(traceback.format_exc())
        raise
