package com.MattUng;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.util.Msg;

import java.util.*;

/**
 * Builds a CALL-only call graph and returns structured JSON (as a String).
 *
 * Root resolution strategy (in order):
 *  1) Symbols marked isExternalEntryPoint() (often exports / entry-ish)
 *  2) Functions named like main/_start/start/WinMain/DllMain/etc if present
 *  3) Fallback: lowest-address function (weak fallback, but better than nothing)
 *
 * Graph is bounded via maxDepth and maxNodes to keep payloads manageable for MCP.
 */
public final class CallGraphBuilder {

    private CallGraphBuilder() {}

    public static String build(Program program, int maxDepth, int maxNodes) {
        if (program == null) {
            return errorJson("No program loaded");
        }
        maxDepth = clamp(maxDepth, 0, 50);
        maxNodes = clamp(maxNodes, 1, 200000);

        FunctionManager fm = program.getFunctionManager();
        Listing listing = program.getListing();
        SymbolTable symtab = program.getSymbolTable();

        // --- pick roots ---
        List<Function> roots = resolveRoots(program, fm, symtab);

        // --- BFS build ---
        LinkedHashMap<String, Node> nodes = new LinkedHashMap<>();
        ArrayList<Edge> edges = new ArrayList<>();
        ArrayDeque<WorkItem> q = new ArrayDeque<>();
        HashSet<String> enqueued = new HashSet<>();

        for (Function r : roots) {
            Node rn = nodeForFunction(r);
            nodes.put(rn.id, rn);
            WorkItem wi = new WorkItem(r, 0);
            q.add(wi);
            enqueued.add(rn.id);
        }

        boolean truncated = false;

        while (!q.isEmpty()) {
            WorkItem wi = q.removeFirst();
            Function f = wi.fn;
            int depth = wi.depth;

            if (depth >= maxDepth) continue;

            // Scan instructions in function body; find CALL references
            InstructionIterator it = listing.getInstructions(f.getBody(), true);
            while (it.hasNext()) {
                Instruction instr = it.next();
                Reference[] refs = instr.getReferencesFrom();
                if (refs == null || refs.length == 0) continue;

                for (Reference ref : refs) {
                    RefType rt = ref.getReferenceType();
                    if (rt == null || !rt.isCall()) continue;

                    Address to = ref.getToAddress();
                    String site = addrStr(instr.getAddress());

                    // Resolve callee
                    Function callee = null;
                    if (to != null) {
                        callee = fm.getFunctionAt(to);
                        if (callee == null) callee = fm.getFunctionContaining(to);
                    }

                    Node calleeNode;
                    if (callee != null) {
                        calleeNode = nodeForFunction(callee);
                    } else {
                        // external / unresolved / indirect-ish: try symbol name; else use address
                        calleeNode = nodeForUnknown(symtab, to);
                    }

                    // Insert node if new
                    if (!nodes.containsKey(calleeNode.id)) {
                        if (nodes.size() >= maxNodes) {
                            truncated = true;
                            break;
                        }
                        nodes.put(calleeNode.id, calleeNode);
                    }

                    edges.add(new Edge(
                            nodeIdForFunction(f),
                            calleeNode.id,
                            site,
                            "call"
                    ));

                    // Enqueue for expansion if it’s an internal function node
                    if (!calleeNode.external && callee != null) {
                        String calleeId = calleeNode.id;
                        if (!enqueued.contains(calleeId)) {
                            q.addLast(new WorkItem(callee, depth + 1));
                            enqueued.add(calleeId);
                        }
                    }
                }

                if (truncated) break;
            }

            if (truncated) break;
        }

        // --- JSON serialize ---
        return graphJson(program, roots, nodes.values(), edges, maxDepth, maxNodes, truncated);
    }

    // ----------------------------
    // Root resolution
    // ----------------------------

    private static List<Function> resolveRoots(Program program, FunctionManager fm, SymbolTable symtab) {
        LinkedHashMap<String, Function> roots = new LinkedHashMap<>();

        // (1) Symbols marked external entry point (your plugin already uses this concept for exports)
        try {
            SymbolIterator it = symtab.getAllSymbols(true);
            while (it.hasNext()) {
                Symbol s = it.next();
                if (s != null && s.isExternalEntryPoint()) {
                    Address a = s.getAddress();
                    Function f = (a != null) ? fm.getFunctionContaining(a) : null;
                    if (f != null) roots.put(nodeIdForFunction(f), f);
                }
            }
        } catch (Exception e) {
            Msg.debug(CallGraphBuilder.class, "resolveRoots: external entry point scan failed: " + e.getMessage());
        }

        // (2) Common entry-ish names
        String[] names = new String[] {
                "main", "_start", "start", "__start", "entry", "WinMain", "wWinMain",
                "DllMain", "DllMainCRTStartup", "mainCRTStartup"
        };
        for (String n : names) {
            try {
                SymbolIterator sit = symtab.getSymbols(n);
                while (sit.hasNext()) {
                    Symbol s = sit.next();
                    if (s == null) continue;
                    Address a = s.getAddress();
                    Function f = (a != null) ? fm.getFunctionContaining(a) : null;
                    if (f != null) roots.put(nodeIdForFunction(f), f);
                }
            } catch (Exception ignored) {}
        }

        // (3) fallback: lowest-address function
        if (roots.isEmpty()) {
            try {
                FunctionIterator fit = fm.getFunctions(true);
                Function lowest = null;
                while (fit.hasNext()) {
                    Function f = fit.next();
                    if (lowest == null) {
                        lowest = f;
                    } else if (f.getEntryPoint().compareTo(lowest.getEntryPoint()) < 0) {
                        lowest = f;
                    }
                }
                if (lowest != null) roots.put(nodeIdForFunction(lowest), lowest);
            } catch (Exception ignored) {}
        }

        return new ArrayList<>(roots.values());
    }

    // ----------------------------
    // Node/Edge DTO
    // ----------------------------

    private static final class WorkItem {
        final Function fn;
        final int depth;
        WorkItem(Function fn, int depth) { this.fn = fn; this.depth = depth; }
    }

    private static final class Node {
        final String id;        // stable identifier (address-based for internal; symbolic for external)
        final String name;
        final String addr;      // may be null/empty for external-only nodes
        final String namespace;
        final boolean external;

        Node(String id, String name, String addr, String namespace, boolean external) {
            this.id = id;
            this.name = name;
            this.addr = addr;
            this.namespace = namespace;
            this.external = external;
        }
    }

    private static final class Edge {
        final String from;
        final String to;
        final String site;   // callsite address (instruction address)
        final String type;   // "call"

        Edge(String from, String to, String site, String type) {
            this.from = from;
            this.to = to;
            this.site = site;
            this.type = type;
        }
    }

    private static Node nodeForFunction(Function f) {
        String id = nodeIdForFunction(f);
        String name = safe(f.getName());
        String addr = addrStr(f.getEntryPoint());
        String ns = (f.getParentNamespace() != null) ? safe(f.getParentNamespace().getName()) : "Global";
        return new Node(id, name, addr, ns, false);
    }

    private static String nodeIdForFunction(Function f) {
        return addrStr(f.getEntryPoint());
    }

    private static Node nodeForUnknown(SymbolTable symtab, Address to) {
        String addr = (to == null) ? "" : addrStr(to);

        // try best-effort symbol name
        String symName = "";
        String ns = "External";
        boolean external = true;

        try {
            if (to != null) {
                Symbol s = symtab.getPrimarySymbol(to);
                if (s != null) {
                    symName = safe(s.getName());
                    Namespace p = s.getParentNamespace();
                    if (p != null) ns = safe(p.getName());
                }
            }
        } catch (Exception ignored) {}

        String name = !symName.isEmpty() ? symName : (!addr.isEmpty() ? addr : "UNKNOWN_CALL_TARGET");
        String id = (!symName.isEmpty()) ? ("EXTERNAL::" + symName) : ("EXTERNAL::" + name);

        return new Node(id, name, addr, ns, external);
    }

    // ----------------------------
    // JSON serialization (no external deps)
    // ----------------------------

    private static String graphJson(
            Program program,
            List<Function> roots,
            Collection<Node> nodes,
            List<Edge> edges,
            int maxDepth,
            int maxNodes,
            boolean truncated
    ) {
        StringBuilder sb = new StringBuilder(64 * 1024);
        sb.append("{");

        // meta
        sb.append("\"meta\":{");
        sb.append("\"programName\":").append(jsonStr(safe(program.getName()))).append(",");
        sb.append("\"imageBase\":").append(jsonStr(addrStr(program.getImageBase()))).append(",");
        sb.append("\"maxDepth\":").append(maxDepth).append(",");
        sb.append("\"maxNodes\":").append(maxNodes).append(",");
        sb.append("\"truncated\":").append(truncated).append(",");
        sb.append("\"roots\":[");
        for (int i = 0; i < roots.size(); i++) {
            if (i > 0) sb.append(",");
            sb.append(jsonStr(addrStr(roots.get(i).getEntryPoint())));
        }
        sb.append("]");
        sb.append("},");

        // nodes
        sb.append("\"nodes\":[");
        int ni = 0;
        for (Node n : nodes) {
            if (ni++ > 0) sb.append(",");
            sb.append("{");
            sb.append("\"id\":").append(jsonStr(n.id)).append(",");
            sb.append("\"name\":").append(jsonStr(n.name)).append(",");
            sb.append("\"addr\":").append(jsonStr(n.addr)).append(",");
            sb.append("\"namespace\":").append(jsonStr(n.namespace)).append(",");
            sb.append("\"external\":").append(n.external);
            sb.append("}");
        }
        sb.append("],");

        // edges
        sb.append("\"edges\":[");
        for (int i = 0; i < edges.size(); i++) {
            if (i > 0) sb.append(",");
            Edge e = edges.get(i);
            sb.append("{");
            sb.append("\"from\":").append(jsonStr(e.from)).append(",");
            sb.append("\"to\":").append(jsonStr(e.to)).append(",");
            sb.append("\"site\":").append(jsonStr(e.site)).append(",");
            sb.append("\"type\":").append(jsonStr(e.type));
            sb.append("}");
        }
        sb.append("]");

        sb.append("}");
        return sb.toString();
    }

    private static String errorJson(String msg) {
        return "{\"error\":" + jsonStr(msg) + "}";
    }

    private static int clamp(int v, int lo, int hi) {
        return Math.max(lo, Math.min(hi, v));
    }

    private static String safe(String s) {
        return (s == null) ? "" : s;
    }

    private static String addrStr(Address a) {
        return (a == null) ? "" : a.toString();
    }

    private static String jsonStr(String s) {
        if (s == null) return "\"\"";
        StringBuilder out = new StringBuilder(s.length() + 16);
        out.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '\\': out.append("\\\\"); break;
                case '"':  out.append("\\\""); break;
                case '\n': out.append("\\n"); break;
                case '\r': out.append("\\r"); break;
                case '\t': out.append("\\t"); break;
                default:
                    if (c < 0x20) {
                        out.append(String.format("\\u%04x", (int)c));
                    } else {
                        out.append(c);
                    }
            }
        }
        out.append('"');
        return out.toString();
    }
}
