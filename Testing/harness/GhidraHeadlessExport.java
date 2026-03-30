/* ###
 * Repo-local Ghidra headless exporter that writes a structured JSON analysis
 * bundle for the currently loaded program.
 */
//@category Analysis

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;

public class GhidraHeadlessExport extends GhidraScript {

	private String safeString(Object value) {
		return value == null ? "" : String.valueOf(value);
	}

	private String addrString(Address address) {
		return address == null ? "" : address.toString();
	}

	private String sha256ForPath(String path) {
		if (path == null || path.isBlank()) {
			return "";
		}
		try {
			byte[] data = Files.readAllBytes(Path.of(path));
			MessageDigest digest = MessageDigest.getInstance("SHA-256");
			byte[] bytes = digest.digest(data);
			StringBuilder builder = new StringBuilder();
			for (byte b : bytes) {
				builder.append(String.format("%02x", b));
			}
			return builder.toString();
		}
		catch (Exception exc) {
			return "";
		}
	}

	private String dataText(Data data) {
		if (data == null) {
			return "";
		}
		try {
			Object value = data.getValue();
			if (value != null) {
				String text = safeString(value).trim();
				if (!text.isEmpty()) {
					return text;
				}
			}
		}
		catch (Exception ignored) {
		}
		try {
			String text = safeString(data.getDefaultValueRepresentation()).trim();
			if (!text.isEmpty()) {
				return text;
			}
		}
		catch (Exception ignored) {
		}
		return "";
	}

	private boolean isProbableString(Data data) {
		if (data == null) {
			return false;
		}
		try {
			String dataType = safeString(data.getDataType().getName()).toLowerCase();
			if (dataType.contains("string") || dataType.contains("unicode")) {
				return true;
			}
		}
		catch (Exception ignored) {
		}
		return dataText(data).length() >= 4;
	}

	private List<Map<String, Object>> collectSections(Program program) {
		List<Map<String, Object>> sections = new ArrayList<>();
		Memory memory = program.getMemory();
		for (MemoryBlock block : memory.getBlocks()) {
			Map<String, Object> item = new LinkedHashMap<>();
			item.put("name", safeString(block.getName()));
			item.put("start", addrString(block.getStart()));
			item.put("end", addrString(block.getEnd()));
			item.put("size", block.getSize());
			item.put("read", block.isRead());
			item.put("write", block.isWrite());
			item.put("execute", block.isExecute());
			item.put("volatile", block.isVolatile());
			sections.add(item);
		}
		return sections;
	}

	private List<Map<String, Object>> collectImports(Program program) {
		List<Map<String, Object>> imports = new ArrayList<>();
		SymbolTable symbolTable = program.getSymbolTable();
		SymbolIterator iter = symbolTable.getExternalSymbols();
		while (iter.hasNext() && !monitor.isCancelled()) {
			Symbol symbol = iter.next();
			Map<String, Object> item = new LinkedHashMap<>();
			item.put("name", safeString(symbol.getName(true)));
			item.put("address", addrString(symbol.getAddress()));
			item.put("namespace", symbol.getParentNamespace() == null ? "" : safeString(symbol.getParentNamespace().getName()));
			item.put("symbol_type", safeString(symbol.getSymbolType()));
			imports.add(item);
		}
		return imports;
	}

	private List<Map<String, Object>> collectExports(Program program) {
		List<Map<String, Object>> exports = new ArrayList<>();
		try {
			SymbolTable symbolTable = program.getSymbolTable();
			AddressIterator iter = symbolTable.getExternalEntryPointIterator();
			while (iter.hasNext() && !monitor.isCancelled()) {
				Address address = iter.next();
				Symbol symbol = symbolTable.getPrimarySymbol(address);
				Map<String, Object> item = new LinkedHashMap<>();
				item.put("name", symbol == null ? "" : safeString(symbol.getName(true)));
				item.put("address", addrString(address));
				item.put("symbol_type", symbol == null ? "" : safeString(symbol.getSymbolType()));
				exports.add(item);
			}
		}
		catch (Exception ignored) {
		}
		return exports;
	}

	private List<Map<String, Object>> collectStrings(Program program) {
		List<Map<String, Object>> strings = new ArrayList<>();
		Listing listing = program.getListing();
		DataIterator iter = listing.getDefinedData(true);
		Set<String> seen = new LinkedHashSet<>();
		while (iter.hasNext() && !monitor.isCancelled()) {
			Data data = iter.next();
			if (!isProbableString(data)) {
				continue;
			}
			String address = addrString(data.getAddress());
			String value = dataText(data);
			if (value.isEmpty()) {
				continue;
			}
			String key = address + "\u0000" + value;
			if (!seen.add(key)) {
				continue;
			}
			Map<String, Object> item = new LinkedHashMap<>();
			item.put("address", address);
			item.put("value", value);
			item.put("length", data.getLength());
			item.put("data_type", safeString(data.getDataType().getName()));
			strings.add(item);
		}
		return strings;
	}

	private Map<String, Object> collectGlobalRefs(Program program, Map<String, String> importMap) {
		Map<String, Object> result = new LinkedHashMap<>();
		Map<String, List<Map<String, Object>>> refsTo = new LinkedHashMap<>();
		Map<String, List<Map<String, Object>>> refsFrom = new LinkedHashMap<>();
		List<Map<String, Object>> dataItems = new ArrayList<>();

		Listing listing = program.getListing();
		SymbolTable symbolTable = program.getSymbolTable();

		DataIterator dataIter = listing.getDefinedData(true);
		while (dataIter.hasNext() && !monitor.isCancelled()) {
			Data data = dataIter.next();
			String text = dataText(data);
			if (text.isEmpty()) {
				continue;
			}
			Map<String, Object> item = new LinkedHashMap<>();
			item.put("address", addrString(data.getAddress()));
			Symbol symbol = symbolTable.getPrimarySymbol(data.getAddress());
			item.put("label", symbol == null ? "" : safeString(symbol.getName(true)));
			item.put("value", text);
			item.put("data_type", safeString(data.getDataType().getName()));
			dataItems.add(item);
		}

		InstructionIterator instrIter = listing.getInstructions(true);
		while (instrIter.hasNext() && !monitor.isCancelled()) {
			Instruction instruction = instrIter.next();
			String fromAddress = addrString(instruction.getAddress());
			for (Reference ref : instruction.getReferencesFrom()) {
				Map<String, Object> refEntry = new LinkedHashMap<>();
				String toAddress = addrString(ref.getToAddress());
				refEntry.put("from_address", fromAddress);
				refEntry.put("to_address", toAddress);
				refEntry.put("ref_type", safeString(ref.getReferenceType()));
				refEntry.put("operand_index", ref.getOperandIndex());
				Data targetData = listing.getDataAt(ref.getToAddress());
				if (isProbableString(targetData)) {
					refEntry.put("string", dataText(targetData));
				}
				String importName = importMap.get(toAddress);
				if (importName != null && !importName.isEmpty()) {
					refEntry.put("import_name", importName);
				}
				refsFrom.computeIfAbsent(fromAddress, ignored -> new ArrayList<>()).add(refEntry);
				refsTo.computeIfAbsent(toAddress, ignored -> new ArrayList<>()).add(refEntry);
			}
		}

		result.put("refs_to", refsTo);
		result.put("refs_from", refsFrom);
		result.put("data_items", dataItems);
		return result;
	}

	private List<String> buildDisassembly(Listing listing, Function function) {
		List<String> lines = new ArrayList<>();
		try {
			InstructionIterator iter = listing.getInstructions(function.getBody(), true);
			while (iter.hasNext() && !monitor.isCancelled()) {
				Instruction instruction = iter.next();
				String rendered = addrString(instruction.getAddress()) + ": " + safeString(instruction);
				String comment = listing.getComment(CodeUnit.EOL_COMMENT, instruction.getAddress());
				if (comment != null && !comment.isBlank()) {
					rendered = rendered + " ; " + comment;
				}
				lines.add(rendered);
			}
		}
		catch (Exception exc) {
			lines.add("DISASSEMBLY_ERROR: " + safeString(exc));
		}
		return lines;
	}

	private String buildDecompilation(DecompInterface decomp, Function function, List<String> warnings) {
		try {
			DecompileResults result = decomp.decompileFunction(function, 30, monitor);
			if (result == null) {
				warnings.add("Decompiler returned no result for " + safeString(function.getName()));
				return "";
			}
			if (!result.decompileCompleted()) {
				warnings.add("Decompile incomplete for " + safeString(function.getName()) + ": " + safeString(result.getErrorMessage()));
			}
			if (result.getDecompiledFunction() == null) {
				return "";
			}
			return safeString(result.getDecompiledFunction().getC());
		}
		catch (Exception exc) {
			warnings.add("Decompiler exception for " + safeString(function.getName()) + ": " + safeString(exc));
			return "";
		}
	}

	private Map<String, Object> collectFunctions(Program program, Map<String, String> stringsByAddress,
			Map<String, String> importMap, Map<String, List<Map<String, Object>>> refsTo) {
		Map<String, Object> result = new LinkedHashMap<>();
		List<Map<String, Object>> functions = new ArrayList<>();
		List<Map<String, Object>> callGraph = new ArrayList<>();
		List<String> warnings = new ArrayList<>();
		List<String> failures = new ArrayList<>();

		Listing listing = program.getListing();
		DecompInterface decomp = new DecompInterface();
		try {
			decomp.openProgram(program);
		}
		catch (Exception exc) {
			failures.add("Failed to open decompiler: " + safeString(exc));
		}

		FunctionIterator functionIter = program.getFunctionManager().getFunctions(true);
		List<Function> allFunctions = new ArrayList<>();
		while (functionIter.hasNext() && !monitor.isCancelled()) {
			allFunctions.add(functionIter.next());
		}

		for (Function function : allFunctions) {
			String entry = addrString(function.getEntryPoint());
			List<Map<String, Object>> callers = new ArrayList<>();
			try {
				for (Function caller : function.getCallingFunctions(monitor)) {
					Map<String, Object> item = new LinkedHashMap<>();
					item.put("name", safeString(caller.getName()));
					item.put("address", addrString(caller.getEntryPoint()));
					callers.add(item);
				}
			}
			catch (Exception ignored) {
			}

			List<Map<String, Object>> callees = new ArrayList<>();
			try {
				for (Function callee : function.getCalledFunctions(monitor)) {
					String calleeAddress = addrString(callee.getEntryPoint());
					String calleeName = safeString(callee.getName());
					Map<String, Object> item = new LinkedHashMap<>();
					item.put("name", calleeName);
					item.put("address", calleeAddress);
					callees.add(item);

					Map<String, Object> edge = new LinkedHashMap<>();
					edge.put("caller_name", safeString(function.getName()));
					edge.put("caller_address", entry);
					edge.put("callee_name", calleeName);
					edge.put("callee_address", calleeAddress);
					callGraph.add(edge);
				}
			}
			catch (Exception ignored) {
			}

			List<Map<String, Object>> stringRefs = new ArrayList<>();
			List<Map<String, Object>> importRefs = new ArrayList<>();
			Set<String> seenStrings = new LinkedHashSet<>();
			Set<String> seenImports = new LinkedHashSet<>();
			InstructionIterator bodyIter = listing.getInstructions(function.getBody(), true);
			while (bodyIter.hasNext() && !monitor.isCancelled()) {
				Instruction instruction = bodyIter.next();
				for (Reference ref : instruction.getReferencesFrom()) {
					String toAddress = addrString(ref.getToAddress());
					String stringValue = stringsByAddress.get(toAddress);
					if (stringValue != null) {
						String key = toAddress + "\u0000" + stringValue;
						if (seenStrings.add(key)) {
							Map<String, Object> item = new LinkedHashMap<>();
							item.put("address", toAddress);
							item.put("value", stringValue);
							stringRefs.add(item);
						}
					}
					String importName = importMap.get(toAddress);
					if (importName != null) {
						String key = toAddress + "\u0000" + importName;
						if (seenImports.add(key)) {
							Map<String, Object> item = new LinkedHashMap<>();
							item.put("address", toAddress);
							item.put("name", importName);
							importRefs.add(item);
						}
					}
				}
			}

			Map<String, Object> item = new LinkedHashMap<>();
			item.put("name", safeString(function.getName()));
			item.put("address", entry);
			item.put("entry", entry);
			item.put("signature", safeString(function.getSignature()));
			item.put("prototype", safeString(function.getPrototypeString(true, true)));
			item.put("namespace", function.getParentNamespace() == null ? "" : safeString(function.getParentNamespace().getName()));
			item.put("is_external", function.isExternal());
			item.put("is_thunk", function.isThunk());
			item.put("callers", callers);
			item.put("callees", callees);
			item.put("xref_count", refsTo.getOrDefault(entry, List.of()).size());
			item.put("string_refs", stringRefs);
			item.put("import_refs", importRefs);
			item.put("decompilation", buildDecompilation(decomp, function, warnings));
			item.put("disassembly", buildDisassembly(listing, function));
			functions.add(item);
		}

		try {
			decomp.dispose();
		}
		catch (Exception ignored) {
		}

		result.put("functions", functions);
		result.put("call_graph", callGraph);
		result.put("warnings", warnings);
		result.put("failures", failures);
		return result;
	}

	private Map<String, String> bestEffortEntryPoint(Program program, List<Map<String, Object>> functions) {
		SymbolTable symbolTable = program.getSymbolTable();
		for (String name : List.of("entry", "entry0", "main", "WinMain", "_start", "start")) {
			try {
				SymbolIterator iter = symbolTable.getSymbols(name);
				if (iter.hasNext()) {
					Symbol symbol = iter.next();
					Map<String, String> entry = new LinkedHashMap<>();
					entry.put("name", safeString(symbol.getName(true)));
					entry.put("address", addrString(symbol.getAddress()));
					return entry;
				}
			}
			catch (Exception ignored) {
			}
		}
		if (!functions.isEmpty()) {
			Map<String, String> entry = new LinkedHashMap<>();
			entry.put("name", safeString(functions.get(0).get("name")));
			entry.put("address", safeString(functions.get(0).get("address")));
			return entry;
		}
		Map<String, String> empty = new LinkedHashMap<>();
		empty.put("name", "");
		empty.put("address", "");
		return empty;
	}

	private List<Map<String, Object>> determineRootFunctions(List<Map<String, Object>> functions) {
		List<Map<String, Object>> roots = new ArrayList<>();
		for (Map<String, Object> function : functions) {
			String name = safeString(function.get("name"));
			@SuppressWarnings("unchecked")
			List<Map<String, Object>> callers = (List<Map<String, Object>>) function.get("callers");
			boolean namedEntry = List.of("entry", "entry0", "main", "WinMain", "_start", "start").contains(name);
			if (namedEntry || callers == null || callers.isEmpty()) {
				Map<String, Object> item = new LinkedHashMap<>();
				item.put("name", name);
				item.put("address", safeString(function.get("address")));
				roots.add(item);
			}
			if (roots.size() >= 12) {
				break;
			}
		}
		return roots;
	}

	@Override
	public void run() throws Exception {
		if (currentProgram == null) {
			throw new IllegalStateException("No current program is loaded in Ghidra");
		}

		String[] args = getScriptArgs();
		if (args.length < 1) {
			throw new IllegalArgumentException("Output JSON path argument is required");
		}

		File outputFile = new File(args[0]).getAbsoluteFile();
		File outputDir = outputFile.getParentFile();
		if (outputDir != null && !outputDir.exists()) {
			outputDir.mkdirs();
		}

		Program program = currentProgram;
		long generatedAtEpoch = System.currentTimeMillis() / 1000L;

		List<Map<String, Object>> sections = collectSections(program);
		List<Map<String, Object>> imports = collectImports(program);
		Map<String, String> importMap = new LinkedHashMap<>();
		for (Map<String, Object> item : imports) {
			importMap.put(safeString(item.get("address")), safeString(item.get("name")));
		}
		List<Map<String, Object>> exports = collectExports(program);
		List<Map<String, Object>> strings = collectStrings(program);
		Map<String, String> stringsByAddress = new LinkedHashMap<>();
		for (Map<String, Object> item : strings) {
			stringsByAddress.put(safeString(item.get("address")), safeString(item.get("value")));
		}

		Map<String, Object> globalRefs = collectGlobalRefs(program, importMap);
		@SuppressWarnings("unchecked")
		Map<String, List<Map<String, Object>>> refsTo =
			(Map<String, List<Map<String, Object>>>) globalRefs.get("refs_to");
		@SuppressWarnings("unchecked")
		Map<String, List<Map<String, Object>>> refsFrom =
			(Map<String, List<Map<String, Object>>>) globalRefs.get("refs_from");
		@SuppressWarnings("unchecked")
		List<Map<String, Object>> dataItems =
			(List<Map<String, Object>>) globalRefs.get("data_items");

		Map<String, Object> functionData = collectFunctions(program, stringsByAddress, importMap, refsTo);
		@SuppressWarnings("unchecked")
		List<Map<String, Object>> functions = (List<Map<String, Object>>) functionData.get("functions");
		@SuppressWarnings("unchecked")
		List<Map<String, Object>> callGraph = (List<Map<String, Object>>) functionData.get("call_graph");
		@SuppressWarnings("unchecked")
		List<String> warnings = (List<String>) functionData.get("warnings");
		@SuppressWarnings("unchecked")
		List<String> failures = (List<String>) functionData.get("failures");

		int xrefCount = 0;
		for (List<Map<String, Object>> items : refsFrom.values()) {
			xrefCount += items.size();
		}

		Map<String, String> entry = bestEffortEntryPoint(program, functions);
		List<Map<String, Object>> rootFunctions = determineRootFunctions(functions);

		Map<String, Object> programInfo = new LinkedHashMap<>();
		programInfo.put("name", safeString(program.getName()));
		try {
			programInfo.put("ghidraProjectPath", safeString(program.getDomainFile().getPathname()));
		}
		catch (Exception exc) {
			programInfo.put("ghidraProjectPath", "");
		}
		String executablePath = safeString(program.getExecutablePath());
		programInfo.put("executablePath", executablePath);
		programInfo.put("executableMD5", safeString(program.getExecutableMD5()));
		programInfo.put("executableSHA256", sha256ForPath(executablePath));
		programInfo.put("language", safeString(program.getLanguageID().getIdAsString()));
		programInfo.put("compiler", safeString(program.getCompilerSpec().getCompilerSpecID().getIdAsString()));
		programInfo.put("endianness", program.getLanguage().isBigEndian() ? "big" : "little");
		programInfo.put("imageBase", addrString(program.getImageBase()));
		programInfo.put("entryPoint", safeString(entry.get("address")));

		Map<String, Object> counts = new LinkedHashMap<>();
		counts.put("functions", functions.size());
		counts.put("strings", strings.size());
		counts.put("imports", imports.size());
		counts.put("exports", exports.size());
		counts.put("references", xrefCount);
		counts.put("data_items", dataItems.size());

		Map<String, Object> payload = new LinkedHashMap<>();
		payload.put("schema_version", 1);
		payload.put("generated_at_epoch", generatedAtEpoch);
		payload.put("source", "ghidra_headless_export");
		payload.put("program", programInfo);
		payload.put("counts", counts);
		payload.put("sections", sections);
		payload.put("imports", imports);
		payload.put("exports", exports);
		payload.put("strings", strings);
		payload.put("data_items", dataItems);
		payload.put("functions", functions);
		payload.put("call_graph", callGraph);
		payload.put("refs_to", refsTo);
		payload.put("refs_from", refsFrom);
		payload.put("root_functions", rootFunctions);
		payload.put("autoAnalysisWarnings", warnings);
		payload.put("autoAnalysisFailures", failures);

		Gson gson = new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create();
		try (FileWriter writer = new FileWriter(outputFile)) {
			gson.toJson(payload, writer);
		}

		println("Wrote Ghidra headless export to " + outputFile.getAbsolutePath());
	}
}
