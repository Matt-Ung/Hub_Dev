package com.MattUng;

import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.app.plugin.core.analysis.AnalysisWorker;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.GlobalNamespace;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.LocalSymbolMap;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.HighFunctionDBUtil.ReturnCommitOption;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.services.CodeViewerService;
import ghidra.app.services.ProgramManager;
import ghidra.app.util.importer.AutoImporter;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.LoadResults;
import ghidra.app.util.PseudoDisassembler;
import ghidra.app.cmd.function.SetVariableNameCmd;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.listing.LocalVariableImpl;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.framework.main.AppInfo;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.Project;
import ghidra.program.util.ProgramLocation;
import ghidra.util.Msg;
import ghidra.util.InvalidNameException;
import ghidra.util.task.ConsoleTaskMonitor;
import ghidra.util.task.TaskMonitor;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.EnumDataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.Undefined1DataType;
import ghidra.program.model.listing.Variable;
import ghidra.app.decompiler.component.DecompilerUtils;
import ghidra.app.decompiler.ClangToken;
import ghidra.framework.options.Options;



import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import javax.swing.SwingUtilities;
import java.io.File;
import java.io.InputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.lang.reflect.Method;
import java.lang.reflect.InvocationTargetException;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.URL;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;

@PluginInfo(
    status = PluginStatus.RELEASED,
    packageName = ghidra.app.DeveloperPluginPackage.NAME,
    category = PluginCategoryNames.ANALYSIS,
    shortDescription = "HTTP server plugin",
    description = "Starts an embedded HTTP server to expose program data. Port configurable via Tool Options."
)
public class GhidraMCPPlugin extends ProgramPlugin {
    /*
     * This extension is based on LaurieWired's original GhidraMCP project:
     * https://github.com/LaurieWired/GhidraMCP
     *
     * This fork keeps the live HTTP bridge model but extends it for the
     * Hub_Dev workflow, including automation hooks, guarded mutation behavior,
     * and managed unpack/import helpers.
     */

    private HttpServer server;
    private static final String OPTION_CATEGORY_NAME = "GhidraMCP HTTP Server";
    private static final String PORT_OPTION_NAME = "Server Port";
    private static final int DEFAULT_PORT = 8080;
    private static final String AUTOMATION_OPTION_CATEGORY_NAME = "GhidraMCP Automation";
    private static final String AUTO_WORKFLOW_ENABLED_OPTION_NAME =
        "Trigger Multi-Agent workflow after auto-analysis";
    private static final String AUTO_WORKFLOW_URL_OPTION_NAME = "Multi-Agent trigger URL";
    private static final String AUTO_WORKFLOW_REQUEST_PROFILE_OPTION_NAME = "Automation request profile";
    private static final String DEFAULT_AUTO_WORKFLOW_URL = "http://127.0.0.1:7861/automation/ghidra-load";
    private static final String DEFAULT_AUTO_WORKFLOW_REQUEST_PROFILE = "technical_report";
    private final Map<String, String> autoWorkflowTriggerFingerprints = Collections.synchronizedMap(new HashMap<>());

    private static final class GraphRootSelection {
        final List<Function> roots;
        final String strategy;
        final String error;

        GraphRootSelection(List<Function> roots, String strategy, String error) {
            this.roots = roots;
            this.strategy = strategy;
            this.error = error;
        }
    }

    private static final class StructFieldSpec {
        final String name;
        final String typeName;
        final int count;
        final String comment;

        StructFieldSpec(String name, String typeName, int count, String comment) {
            this.name = name;
            this.typeName = typeName;
            this.count = Math.max(1, count);
            this.comment = comment == null ? "" : comment;
        }
    }

    private static final class EnumMemberSpec {
        final String name;
        final long value;
        final String comment;

        EnumMemberSpec(String name, long value, String comment) {
            this.name = name;
            this.value = value;
            this.comment = comment == null ? "" : comment;
        }
    }

    public GhidraMCPPlugin(PluginTool tool) {
        super(tool);
        Msg.info(this, "GhidraMCPPlugin loading...");

        // Register the configuration option
        Options options = tool.getOptions(OPTION_CATEGORY_NAME);
        options.registerOption(PORT_OPTION_NAME, DEFAULT_PORT,
            null, // No help location for now
            "The network port number the embedded HTTP server will listen on. " +
            "Requires Ghidra restart or plugin reload to take effect after changing.");

        Options automationOptions = tool.getOptions(AUTOMATION_OPTION_CATEGORY_NAME);
        automationOptions.registerOption(
            AUTO_WORKFLOW_ENABLED_OPTION_NAME,
            false,
            null,
            "If enabled, queue a trigger to the local Multi-Agent-WF automation endpoint after the active program's auto-analysis settles."
        );
        automationOptions.registerOption(
            AUTO_WORKFLOW_URL_OPTION_NAME,
            DEFAULT_AUTO_WORKFLOW_URL,
            null,
            "HTTP endpoint exposed by multi_agent_wf/main.py for automated Ghidra load triggers."
        );
        automationOptions.registerOption(
            AUTO_WORKFLOW_REQUEST_PROFILE_OPTION_NAME,
            DEFAULT_AUTO_WORKFLOW_REQUEST_PROFILE,
            null,
            "Automation request profile sent to the local Multi-Agent-WF trigger. Supported values: technical_report, detailed_report, workplan."
        );

        try {
            startServer();
        }
        catch (IOException e) {
            Msg.error(this, "Failed to start HTTP server", e);
        }
        Msg.info(this, "GhidraMCPPlugin loaded!");
    }

    @Override
    public void init() {
        super.init();
        Program currentProgram = getCurrentProgram();
        if (currentProgram != null) {
            maybeQueueAutoWorkflowTrigger(currentProgram);
        }
    }

    @Override
    protected void programActivated(Program program) {
        super.programActivated(program);
        maybeQueueAutoWorkflowTrigger(program);
    }

    @Override
    protected void programClosed(Program program) {
        super.programClosed(program);
        autoWorkflowTriggerFingerprints.remove(getProgramAutomationBaseKey(program));
    }

    private void maybeQueueAutoWorkflowTrigger(Program program) {
        if (program == null) {
            Msg.info(this, "Auto workflow trigger not queued because no active program is available.");
            return;
        }
        if (!isAutoWorkflowEnabled()) {
            Msg.info(
                this,
                "Auto workflow trigger not queued for "
                    + safe(program.getName())
                    + " because the automation option is disabled."
            );
            return;
        }

        String baseKey = getProgramAutomationBaseKey(program);
        String fingerprint = getProgramAutomationFingerprint(program);
        String previousFingerprint = autoWorkflowTriggerFingerprints.get(baseKey);
        if (previousFingerprint != null && previousFingerprint.equals(fingerprint)) {
            Msg.info(
                this,
                "Auto workflow trigger not re-queued for "
                    + safe(program.getName())
                    + " because the automation fingerprint is unchanged."
            );
            return;
        }
        Msg.info(
            this,
            "Queueing auto workflow trigger for "
                + safe(program.getName())
                + " after auto-analysis settles. URL="
                + safe(String.valueOf(getAutoWorkflowUrl()))
        );
        autoWorkflowTriggerFingerprints.put(baseKey, fingerprint);

        Thread worker = new Thread(() -> waitForAutoAnalysisAndTrigger(program, baseKey, fingerprint),
            "GhidraMCP-AutoWorkflow-" + Integer.toHexString(System.identityHashCode(program)));
        worker.setDaemon(true);
        worker.start();
    }

    private boolean isAutoWorkflowEnabled() {
        Options automationOptions = tool.getOptions(AUTOMATION_OPTION_CATEGORY_NAME);
        return automationOptions.getBoolean(AUTO_WORKFLOW_ENABLED_OPTION_NAME, false);
    }

    private String getAutoWorkflowUrl() {
        Options automationOptions = tool.getOptions(AUTOMATION_OPTION_CATEGORY_NAME);
        return trimToNull(automationOptions.getString(AUTO_WORKFLOW_URL_OPTION_NAME, DEFAULT_AUTO_WORKFLOW_URL));
    }

    private String getAutoWorkflowRequestProfile() {
        Options automationOptions = tool.getOptions(AUTOMATION_OPTION_CATEGORY_NAME);
        String value = trimToNull(
            automationOptions.getString(
                AUTO_WORKFLOW_REQUEST_PROFILE_OPTION_NAME,
                DEFAULT_AUTO_WORKFLOW_REQUEST_PROFILE
            )
        );
        return value == null ? DEFAULT_AUTO_WORKFLOW_REQUEST_PROFILE : value;
    }

    private String getProgramAutomationBaseKey(Program program) {
        if (program == null) {
            return "";
        }

        String domainPath = "";
        try {
            if (program.getDomainFile() != null) {
                domainPath = safe(program.getDomainFile().getPathname());
            }
        } catch (Exception ignored) {}

        String executablePath = "";
        try {
            executablePath = safe(program.getExecutablePath());
        } catch (Exception ignored) {}

        String base = !domainPath.isEmpty()
            ? domainPath
            : (!executablePath.isEmpty() ? executablePath : safe(program.getName()));
        if (base.isEmpty()) {
            base = Integer.toHexString(System.identityHashCode(program));
        }
        return base;
    }

    private String getProgramModificationToken(Program program) {
        if (program == null) {
            return "";
        }

        try {
            Method method = program.getClass().getMethod("getModificationNumber");
            Object value = method.invoke(program);
            return safe(String.valueOf(value));
        } catch (Exception ignored) {}

        return "";
    }

    private String getProgramAutomationFingerprint(Program program) {
        if (program == null) {
            return "";
        }

        String sha256 = "";
        try {
            sha256 = safe(program.getExecutableSHA256());
        } catch (Exception ignored) {}
        String modificationToken = getProgramModificationToken(program);
        String fingerprint = sha256 + "|" + modificationToken;
        if ("|".equals(fingerprint)) {
            fingerprint = getProgramAutomationBaseKey(program) + "|" + safe(program.getName());
        }
        return fingerprint;
    }

    private void waitForAutoAnalysisAndTrigger(Program program, String baseKey, String fingerprint) {
        try {
            AutoAnalysisManager manager = AutoAnalysisManager.getAnalysisManager(program);
            Msg.info(this, "Scheduling post-analysis workflow trigger worker for " + safe(program.getName()));
            boolean scheduled = manager.scheduleWorker(new AnalysisWorker() {
                @Override
                public String getWorkerName() {
                    return "WFTrigger";
                }

                @Override
                public boolean analysisWorkerCallback(Program analyzedProgram, Object workerContext, TaskMonitor monitor)
                        throws Exception {
                    postAutoWorkflowTrigger(analyzedProgram, baseKey, fingerprint);
                    return true;
                }
            }, null, true, TaskMonitor.DUMMY);

            if (!scheduled) {
                autoWorkflowTriggerFingerprints.remove(baseKey);
                Msg.warn(this, "Auto workflow trigger was not scheduled for program " + safe(program.getName()));
            }
        } catch (Exception e) {
            autoWorkflowTriggerFingerprints.remove(baseKey);
            Msg.error(this, "Failed to queue auto workflow trigger for " + safe(program.getName()), e);
        }
    }

    private void postAutoWorkflowTrigger(Program program, String baseKey, String fingerprint) {
        String targetUrl = getAutoWorkflowUrl();
        if (program == null || targetUrl == null) {
            autoWorkflowTriggerFingerprints.remove(baseKey);
            Msg.info(
                this,
                "Auto workflow trigger skipped because program or trigger URL was unavailable for "
                    + safe(program == null ? "<null>" : program.getName())
            );
            return;
        }

        HttpURLConnection connection = null;
        try {
            Msg.info(this, "Posting auto workflow trigger for " + safe(program.getName()) + " to " + targetUrl);
            URL url = new URL(targetUrl);
            connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("POST");
            connection.setDoOutput(true);
            connection.setConnectTimeout(1500);
            connection.setReadTimeout(5000);
            connection.setRequestProperty("Content-Type", "application/json; charset=utf-8");

            byte[] body = buildAutoWorkflowPayload(program, baseKey, fingerprint).getBytes(StandardCharsets.UTF_8);
            connection.setFixedLengthStreamingMode(body.length);
            try (OutputStream os = connection.getOutputStream()) {
                os.write(body);
            }

            int status = connection.getResponseCode();
            String response = readHttpResponseBody(connection);
            Msg.info(
                this,
                "Auto workflow trigger HTTP result for "
                    + safe(program.getName())
                    + ": status="
                    + status
                    + (response.isEmpty() ? "" : (", body=" + response))
            );
            if (status >= 200 && status < 300) {
                if (response.contains("\"accepted\":false")) {
                    Msg.info(this, "Multi-Agent workflow auto-trigger skipped for " + safe(program.getName()) + " (duplicate or already triaged).");
                    return;
                }
                Msg.info(this, "Auto-triggered Multi-Agent workflow for " + safe(program.getName()));
                return;
            }
            if (status == 409) {
                autoWorkflowTriggerFingerprints.remove(baseKey);
                Msg.info(this, "Multi-Agent workflow is already running; skipped auto-trigger for " + safe(program.getName()));
                return;
            }
            autoWorkflowTriggerFingerprints.remove(baseKey);
            Msg.warn(
                this,
                "Multi-Agent workflow trigger failed for " + safe(program.getName()) +
                " with HTTP " + status + (response.isEmpty() ? "" : (": " + response))
            );
        } catch (IOException e) {
            autoWorkflowTriggerFingerprints.remove(baseKey);
            Msg.info(
                this,
                "Multi-Agent-WF trigger endpoint not reachable at " + targetUrl +
                "; skipping auto-trigger for " + safe(program.getName())
            );
        } finally {
            if (connection != null) {
                connection.disconnect();
            }
        }
    }

    private String buildAutoWorkflowPayload(Program program, String baseKey, String fingerprint) {
        String domainPath = "";
        try {
            if (program.getDomainFile() != null) {
                domainPath = safe(program.getDomainFile().getPathname());
            }
        } catch (Exception ignored) {}

        String languageId = "";
        try {
            if (program.getLanguageID() != null) {
                languageId = program.getLanguageID().getIdAsString();
            }
        } catch (Exception ignored) {}

        String compilerId = "";
        try {
            if (program.getCompilerSpec() != null && program.getCompilerSpec().getCompilerSpecID() != null) {
                compilerId = program.getCompilerSpec().getCompilerSpecID().getIdAsString();
            }
        } catch (Exception ignored) {}

        String imageBase = "";
        try {
            if (program.getImageBase() != null) {
                imageBase = program.getImageBase().toString();
            }
        } catch (Exception ignored) {}

        List<String> warnings = new ArrayList<>();
        List<String> failures = new ArrayList<>();
        List<String> sectionSummary = buildAutomationSectionSummary(program, 12, warnings);
        List<String> importSummary = buildAutomationImportSummary(program, 20, warnings);
        List<String> exportSummary = buildAutomationExportSummary(program, 12, warnings);
        List<String> rootFunctions = buildAutomationRootSummary(program, 8, warnings);
        String entryPoint = "";
        if (!rootFunctions.isEmpty()) {
            String firstRoot = rootFunctions.get(0);
            int atIdx = firstRoot.indexOf(" @ ");
            if (atIdx >= 0) {
                int endIdx = firstRoot.indexOf(" [", atIdx);
                entryPoint = endIdx > atIdx
                    ? firstRoot.substring(atIdx + 3, endIdx).trim()
                    : firstRoot.substring(atIdx + 3).trim();
            }
        }

        return "{"
            + "\"source\":\"ghidra_auto_analysis\","
            + "\"automation_program_key\":" + jsonStr(baseKey) + ","
            + "\"automation_signature\":" + jsonStr(fingerprint) + ","
            + "\"analysis_token\":" + jsonStr(fingerprint) + ","
            + "\"automation_request_profile\":" + jsonStr(getAutoWorkflowRequestProfile()) + ","
            + "\"analysis_completed_at_epoch_ms\":" + System.currentTimeMillis() + ","
            + "\"program_name\":" + jsonStr(safe(program.getName())) + ","
            + "\"ghidra_project_path\":" + jsonStr(domainPath) + ","
            + "\"executable_path\":" + jsonStr(safe(program.getExecutablePath())) + ","
            + "\"executable_md5\":" + jsonStr(safe(program.getExecutableMD5())) + ","
            + "\"executable_sha256\":" + jsonStr(safe(program.getExecutableSHA256())) + ","
            + "\"language\":" + jsonStr(safe(languageId)) + ","
            + "\"compiler\":" + jsonStr(safe(compilerId)) + ","
            + "\"image_base\":" + jsonStr(safe(imageBase)) + ","
            + "\"entry_point\":" + jsonStr(safe(entryPoint)) + ","
            + "\"section_summary\":" + jsonStrArray(sectionSummary) + ","
            + "\"import_summary\":" + jsonStrArray(importSummary) + ","
            + "\"export_summary\":" + jsonStrArray(exportSummary) + ","
            + "\"root_functions\":" + jsonStrArray(rootFunctions) + ","
            + "\"counts\":{"
                + "\"functions\":" + countFunctions(program) + ","
                + "\"imports\":" + countImports(program) + ","
                + "\"exports\":" + countExports(program) + ","
                + "\"strings\":" + countDefinedStrings(program) + ","
                + "\"external_references\":" + countExternalReferences(program) + ","
                + "\"segments\":" + program.getMemory().getBlocks().length
            + "},"
            + "\"program_info\":" + getProgramInfoJson() + ","
            + "\"auto_analysis_warnings\":" + jsonStrArray(warnings) + ","
            + "\"auto_analysis_failures\":" + jsonStrArray(failures)
            + "}";
    }

    private String readHttpResponseBody(HttpURLConnection connection) throws IOException {
        InputStream stream = null;
        try {
            stream = connection.getResponseCode() >= 400 ? connection.getErrorStream() : connection.getInputStream();
        } catch (IOException ignored) {
            stream = connection.getErrorStream();
        }
        if (stream == null) {
            return "";
        }
        try (InputStream in = stream) {
            return new String(in.readAllBytes(), StandardCharsets.UTF_8).trim();
        }
    }

    private void startServer() throws IOException {
        // Read the configured port
        Options options = tool.getOptions(OPTION_CATEGORY_NAME);
        int port = options.getInt(PORT_OPTION_NAME, DEFAULT_PORT);

        // Stop existing server if running (e.g., if plugin is reloaded)
        if (server != null) {
            Msg.info(this, "Stopping existing HTTP server before starting new one.");
            server.stop(0);
            server = null;
        }

        server = HttpServer.create(new InetSocketAddress(port), 0);

        // Each listing endpoint uses offset & limit from query params:
        server.createContext("/methods", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, getAllFunctionNames(offset, limit));
        });

        server.createContext("/classes", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, getAllClassNames(offset, limit));
        });

        server.createContext("/decompile", exchange -> {
            String name = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            sendResponse(exchange, decompileFunctionByName(name));
        });

        server.createContext("/renameFunction", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String response = renameFunction(params.get("oldName"), params.get("newName"))
                    ? "Renamed successfully" : "Rename failed";
            sendResponse(exchange, response);
        });

        server.createContext("/renameData", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            renameDataAtAddress(params.get("address"), params.get("newName"));
            sendResponse(exchange, "Rename data attempted");
        });

        server.createContext("/renameVariable", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String functionName = params.get("functionName");
            String oldName = params.get("oldName");
            String newName = params.get("newName");
            String result = renameVariableInFunction(functionName, oldName, newName);
            sendResponse(exchange, result);
        });

        server.createContext("/segments", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, listSegments(offset, limit));
        });

        server.createContext("/imports", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, listImports(offset, limit));
        });

        server.createContext("/exports", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, listExports(offset, limit));
        });

        server.createContext("/namespaces", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, listNamespaces(offset, limit));
        });

        server.createContext("/data", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, listDefinedData(offset, limit));
        });

        server.createContext("/searchFunctions", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String searchTerm = qparams.get("query");
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, searchFunctionsByName(searchTerm, offset, limit));
        });

        // New API endpoints based on requirements
        
        server.createContext("/get_function_by_address", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            sendResponse(exchange, getFunctionByAddress(address));
        });

        server.createContext("/get_current_address", exchange -> {
            sendResponse(exchange, getCurrentAddress());
        });

        server.createContext("/get_current_function", exchange -> {
            sendResponse(exchange, getCurrentFunction());
        });

        server.createContext("/list_functions", exchange -> {
            sendResponse(exchange, listFunctions());
        });

        server.createContext("/decompile_function", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            sendResponse(exchange, decompileFunctionByAddress(address));
        });

        server.createContext("/disassemble_function", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            sendResponse(exchange, disassembleFunction(address));
        });

        server.createContext("/set_decompiler_comment", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String address = params.get("address");
            String comment = params.get("comment");
            boolean success = setDecompilerComment(address, comment);
            sendResponse(exchange, success ? "Comment set successfully" : "Failed to set comment");
        });

        server.createContext("/set_disassembly_comment", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String address = params.get("address");
            String comment = params.get("comment");
            boolean success = setDisassemblyComment(address, comment);
            sendResponse(exchange, success ? "Comment set successfully" : "Failed to set comment");
        });

        server.createContext("/rename_function_by_address", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String functionAddress = params.get("function_address");
            String newName = params.get("new_name");
            boolean success = renameFunctionByAddress(functionAddress, newName);
            sendResponse(exchange, success ? "Function renamed successfully" : "Failed to rename function");
        });

        server.createContext("/set_function_prototype", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String functionAddress = params.get("function_address");
            String prototype = params.get("prototype");

            // Call the set prototype function and get detailed result
            PrototypeResult result = setFunctionPrototype(functionAddress, prototype);

            if (result.isSuccess()) {
                // Even with successful operations, include any warning messages for debugging
                String successMsg = "Function prototype set successfully";
                if (!result.getErrorMessage().isEmpty()) {
                    successMsg += "\n\nWarnings/Debug Info:\n" + result.getErrorMessage();
                }
                sendResponse(exchange, successMsg);
            } else {
                // Return the detailed error message to the client
                sendResponse(exchange, "Failed to set function prototype: " + result.getErrorMessage());
            }
        });

        server.createContext("/set_local_variable_type", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String functionAddress = params.get("function_address");
            String variableName = params.get("variable_name");
            String newType = params.get("new_type");

            // Capture detailed information about setting the type
            StringBuilder responseMsg = new StringBuilder();
            responseMsg.append("Setting variable type: ").append(variableName)
                      .append(" to ").append(newType)
                      .append(" in function at ").append(functionAddress).append("\n\n");

            // Attempt to find the data type in various categories
            Program program = getCurrentProgram();
            if (program != null) {
                DataTypeManager dtm = program.getDataTypeManager();
                DataType directType = findDataTypeByNameInAllCategories(dtm, newType);
                if (directType != null) {
                    responseMsg.append("Found type: ").append(directType.getPathName()).append("\n");
                } else if (newType.startsWith("P") && newType.length() > 1) {
                    String baseTypeName = newType.substring(1);
                    DataType baseType = findDataTypeByNameInAllCategories(dtm, baseTypeName);
                    if (baseType != null) {
                        responseMsg.append("Found base type for pointer: ").append(baseType.getPathName()).append("\n");
                    } else {
                        responseMsg.append("Base type not found for pointer: ").append(baseTypeName).append("\n");
                    }
                } else {
                    responseMsg.append("Type not found directly: ").append(newType).append("\n");
                }
            }

            // Try to set the type
            boolean success = setLocalVariableType(functionAddress, variableName, newType);

            String successMsg = success ? "Variable type set successfully" : "Failed to set variable type";
            responseMsg.append("\nResult: ").append(successMsg);

            sendResponse(exchange, responseMsg.toString());
        });

        server.createContext("/apply_data_type_to_data", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String address = params.get("address");
            String dataTypeName = params.get("data_type_name");
            String result = applyDataTypeToData(address, dataTypeName);
            sendResponse(exchange, result);
        });

        server.createContext("/create_struct_type", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String typeName = params.get("type_name");
            String fieldsSpec = params.get("fields_spec");
            boolean replaceExisting = parseBooleanParam(params.get("replace_existing"), false);
            String result = createStructType(typeName, fieldsSpec, replaceExisting);
            sendResponse(exchange, result);
        });

        server.createContext("/create_enum_type", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String typeName = params.get("type_name");
            String membersSpec = params.get("members_spec");
            int byteSize = parseIntOrDefault(params.get("byte_size"), 4);
            boolean replaceExisting = parseBooleanParam(params.get("replace_existing"), false);
            String result = createEnumType(typeName, membersSpec, byteSize, replaceExisting);
            sendResponse(exchange, result);
        });

        server.createContext("/xrefs_to", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, getXrefsTo(address, offset, limit));
        });

        server.createContext("/xrefs_from", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, getXrefsFrom(address, offset, limit));
        });

        server.createContext("/function_xrefs", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String name = qparams.get("name");
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, getFunctionXrefs(name, offset, limit));
        });

        server.createContext("/strings", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            String filter = qparams.get("filter");
            sendResponse(exchange, listDefinedStrings(offset, limit, filter));
        });

        server.createContext("/program_info", exchange -> {
            sendJsonResponse(exchange, getProgramInfoJson());
        });

        server.createContext("/import_executable", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String filePath = params.get("file_path");
            String projectFolder = params.get("project_folder");
            boolean openImportedProgram = parseBooleanParam(params.get("open_imported_program"), true);
            boolean reuseExisting = parseBooleanParam(params.get("reuse_existing"), true);
            sendJsonResponse(
                exchange,
                importExecutableIntoCurrentProject(filePath, projectFolder, openImportedProgram, reuseExisting)
            );
        });
        
        server.createContext("/callgraph_json", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int maxDepth = parseIntOrDefault(qparams.get("maxDepth"), 4);
            int maxNodes = parseIntOrDefault(qparams.get("maxNodes"), 2000);

            Program program = getCurrentProgram();
            GraphRootSelection rootSelection = selectCallGraphRoots(program, qparams);
            if (rootSelection.error != null) {
                sendJsonResponse(exchange, jsonError(rootSelection.error));
                return;
            }

            String json = CallGraphBuilder.build(
                program,
                rootSelection.roots,
                rootSelection.strategy,
                maxDepth,
                maxNodes
            );
            sendJsonResponse(exchange, json);
        });


        server.setExecutor(null);
        new Thread(() -> {
            try {
                server.start();
                Msg.info(this, "GhidraMCP HTTP server started on port " + port);
            } catch (Exception e) {
                Msg.error(this, "Failed to start HTTP server on port " + port + ". Port might be in use.", e);
                server = null; // Ensure server isn't considered running
            }
        }, "GhidraMCP-HTTP-Server").start();
    }

    

    // ----------------------------------------------------------------------------------
    // Pagination-aware listing methods
    // ----------------------------------------------------------------------------------

    private String getAllFunctionNames(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        List<String> names = new ArrayList<>();
        for (Function f : program.getFunctionManager().getFunctions(true)) {
            names.add(f.getName());
        }
        return paginateList(names, offset, limit);
    }

    private String getAllClassNames(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        Set<String> classNames = new HashSet<>();
        for (Symbol symbol : program.getSymbolTable().getAllSymbols(true)) {
            Namespace ns = symbol.getParentNamespace();
            if (ns != null && !ns.isGlobal()) {
                classNames.add(ns.getName());
            }
        }
        // Convert set to list for pagination
        List<String> sorted = new ArrayList<>(classNames);
        Collections.sort(sorted);
        return paginateList(sorted, offset, limit);
    }

    private String listSegments(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        List<String> lines = new ArrayList<>();
        for (MemoryBlock block : program.getMemory().getBlocks()) {
            lines.add(String.format("%s: %s - %s", block.getName(), block.getStart(), block.getEnd()));
        }
        return paginateList(lines, offset, limit);
    }

    private String listImports(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        List<String> lines = new ArrayList<>();
        for (Symbol symbol : program.getSymbolTable().getExternalSymbols()) {
            lines.add(symbol.getName() + " -> " + symbol.getAddress());
        }
        return paginateList(lines, offset, limit);
    }

    private String listExports(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        SymbolTable table = program.getSymbolTable();
        SymbolIterator it = table.getAllSymbols(true);

        List<String> lines = new ArrayList<>();
        while (it.hasNext()) {
            Symbol s = it.next();
            // On older Ghidra, "export" is recognized via isExternalEntryPoint()
            if (s.isExternalEntryPoint()) {
                lines.add(s.getName() + " -> " + s.getAddress());
            }
        }
        return paginateList(lines, offset, limit);
    }

    private String listNamespaces(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        Set<String> namespaces = new HashSet<>();
        for (Symbol symbol : program.getSymbolTable().getAllSymbols(true)) {
            Namespace ns = symbol.getParentNamespace();
            if (ns != null && !(ns instanceof GlobalNamespace)) {
                namespaces.add(ns.getName());
            }
        }
        List<String> sorted = new ArrayList<>(namespaces);
        Collections.sort(sorted);
        return paginateList(sorted, offset, limit);
    }

    private String listDefinedData(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        List<String> lines = new ArrayList<>();
        for (MemoryBlock block : program.getMemory().getBlocks()) {
            DataIterator it = program.getListing().getDefinedData(block.getStart(), true);
            while (it.hasNext()) {
                Data data = it.next();
                if (block.contains(data.getAddress())) {
                    String label   = data.getLabel() != null ? data.getLabel() : "(unnamed)";
                    String valRepr = data.getDefaultValueRepresentation();
                    lines.add(String.format("%s: %s = %s",
                        data.getAddress(),
                        escapeNonAscii(label),
                        escapeNonAscii(valRepr)
                    ));
                }
            }
        }
        return paginateList(lines, offset, limit);
    }

    private String searchFunctionsByName(String searchTerm, int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (searchTerm == null || searchTerm.isEmpty()) return "Search term is required";
    
        List<String> matches = new ArrayList<>();
        for (Function func : program.getFunctionManager().getFunctions(true)) {
            String name = func.getName();
            // simple substring match
            if (name.toLowerCase().contains(searchTerm.toLowerCase())) {
                matches.add(String.format("%s @ %s", name, func.getEntryPoint()));
            }
        }
    
        Collections.sort(matches);
    
        if (matches.isEmpty()) {
            return "No functions matching '" + searchTerm + "'";
        }
        return paginateList(matches, offset, limit);
    }

    private String safe(String s) {
        return (s == null) ? "" : s;
    }

    private String getProgramInfoJson() {
        Program program = getCurrentProgram();
        if (program == null) {
            return "{\"loaded\":false,\"error\":" + jsonStr("No program loaded") + "}";
        }

        ProgramLocation location = getCurrentLocationObject();
        Function currentFunction = getCurrentFunctionObject(program, location);

        String domainPath = "";
        try {
            if (program.getDomainFile() != null) {
                domainPath = safe(program.getDomainFile().getPathname());
            }
        } catch (Exception ignored) {}

        String languageId = "";
        try {
            if (program.getLanguageID() != null) {
                languageId = program.getLanguageID().getIdAsString();
            }
        } catch (Exception ignored) {}

        String compilerId = "";
        try {
            if (program.getCompilerSpec() != null && program.getCompilerSpec().getCompilerSpecID() != null) {
                compilerId = program.getCompilerSpec().getCompilerSpecID().getIdAsString();
            }
        } catch (Exception ignored) {}

        boolean bigEndian = false;
        try {
            bigEndian = program.getLanguage().isBigEndian();
        } catch (Exception ignored) {}

        String imageBase = "";
        try {
            if (program.getImageBase() != null) {
                imageBase = program.getImageBase().toString();
            }
        } catch (Exception ignored) {}

        StringBuilder sb = new StringBuilder(2048);
        sb.append("{");
        sb.append("\"loaded\":true,");
        sb.append("\"program\":{");
        sb.append("\"name\":").append(jsonStr(safe(program.getName()))).append(",");
        sb.append("\"ghidraProjectPath\":").append(jsonStr(domainPath)).append(",");
        sb.append("\"executablePath\":").append(jsonStr(safe(program.getExecutablePath()))).append(",");
        sb.append("\"executableMD5\":").append(jsonStr(safe(program.getExecutableMD5()))).append(",");
        sb.append("\"executableSHA256\":").append(jsonStr(safe(program.getExecutableSHA256()))).append(",");
        sb.append("\"language\":").append(jsonStr(safe(languageId))).append(",");
        sb.append("\"compiler\":").append(jsonStr(safe(compilerId))).append(",");
        sb.append("\"endianness\":").append(jsonStr(bigEndian ? "big" : "little")).append(",");
        sb.append("\"imageBase\":").append(jsonStr(safe(imageBase))).append(",");
        sb.append("\"pointerSize\":").append(program.getDefaultPointerSize());
        sb.append("},");
        sb.append("\"counts\":{");
        sb.append("\"functions\":").append(countFunctions(program)).append(",");
        sb.append("\"imports\":").append(countImports(program)).append(",");
        sb.append("\"exports\":").append(countExports(program)).append(",");
        sb.append("\"segments\":").append(program.getMemory().getBlocks().length);
        sb.append("},");
        sb.append("\"currentLocation\":");
        if (location == null || location.getAddress() == null) {
            sb.append("null");
        } else {
            sb.append("{");
            sb.append("\"address\":").append(jsonStr(location.getAddress().toString())).append(",");
            sb.append("\"function\":");
            if (currentFunction == null) {
                sb.append("null");
            } else {
                sb.append("{");
                sb.append("\"name\":").append(jsonStr(safe(currentFunction.getName()))).append(",");
                sb.append("\"entry\":").append(jsonStr(currentFunction.getEntryPoint().toString())).append(",");
                sb.append("\"signature\":").append(jsonStr(safe(currentFunction.getSignature().toString()))).append(",");
                sb.append("\"namespace\":").append(jsonStr(getNamespaceName(currentFunction.getParentNamespace())));
                sb.append("}");
            }
            sb.append("}");
        }
        sb.append("}");
        return sb.toString();
    }

    private String getNamespaceName(Namespace namespace) {
        return (namespace == null) ? "Global" : safe(namespace.getName());
    }

    private int countFunctions(Program program) {
        int count = 0;
        for (Function ignored : program.getFunctionManager().getFunctions(true)) {
            count++;
        }
        return count;
    }

    private int countImports(Program program) {
        int count = 0;
        for (Symbol ignored : program.getSymbolTable().getExternalSymbols()) {
            count++;
        }
        return count;
    }

    private int countExports(Program program) {
        int count = 0;
        SymbolIterator it = program.getSymbolTable().getAllSymbols(true);
        while (it.hasNext()) {
            Symbol symbol = it.next();
            if (symbol.isExternalEntryPoint()) {
                count++;
            }
        }
        return count;
    }

    private int countDefinedStrings(Program program) {
        if (program == null) {
            return 0;
        }

        int count = 0;
        DataIterator dataIt = program.getListing().getDefinedData(true);
        while (dataIt.hasNext()) {
            Data data = dataIt.next();
            if (data != null && isStringData(data)) {
                count++;
            }
        }
        return count;
    }

    private int countExternalReferences(Program program) {
        if (program == null) {
            return 0;
        }

        int count = 0;
        ReferenceManager refManager = program.getReferenceManager();
        for (Symbol symbol : program.getSymbolTable().getExternalSymbols()) {
            Address address = symbol.getAddress();
            if (address == null) {
                continue;
            }
            ReferenceIterator refs = refManager.getReferencesTo(address);
            while (refs.hasNext()) {
                refs.next();
                count++;
            }
        }
        return count;
    }

    private List<String> buildAutomationSectionSummary(Program program, int maxItems, List<String> warnings) {
        List<String> lines = new ArrayList<>();
        if (program == null) {
            return lines;
        }

        try {
            for (MemoryBlock block : program.getMemory().getBlocks()) {
                if (lines.size() >= maxItems) {
                    break;
                }
                String perms =
                    (block.isRead() ? "r" : "-") +
                    (block.isWrite() ? "w" : "-") +
                    (block.isExecute() ? "x" : "-");
                lines.add(
                    String.format(
                        "%s: %s - %s perms=%s size=%d",
                        block.getName(),
                        block.getStart(),
                        block.getEnd(),
                        perms,
                        block.getSize()
                    )
                );
            }
        } catch (Exception e) {
            warnings.add("Section summary collection failed: " + safe(e.getMessage()));
        }
        return lines;
    }

    private List<String> buildAutomationImportSummary(Program program, int maxItems, List<String> warnings) {
        List<String> lines = new ArrayList<>();
        if (program == null) {
            return lines;
        }

        try {
            for (Symbol symbol : program.getSymbolTable().getExternalSymbols()) {
                if (lines.size() >= maxItems) {
                    break;
                }
                lines.add(symbol.getName() + " -> " + symbol.getAddress());
            }
        } catch (Exception e) {
            warnings.add("Import summary collection failed: " + safe(e.getMessage()));
        }
        return lines;
    }

    private List<String> buildAutomationExportSummary(Program program, int maxItems, List<String> warnings) {
        List<String> lines = new ArrayList<>();
        if (program == null) {
            return lines;
        }

        try {
            SymbolIterator it = program.getSymbolTable().getAllSymbols(true);
            while (it.hasNext() && lines.size() < maxItems) {
                Symbol symbol = it.next();
                if (symbol.isExternalEntryPoint()) {
                    lines.add(symbol.getName() + " -> " + symbol.getAddress());
                }
            }
        } catch (Exception e) {
            warnings.add("Export summary collection failed: " + safe(e.getMessage()));
        }
        return lines;
    }

    private List<String> buildAutomationRootSummary(Program program, int maxItems, List<String> warnings) {
        List<String> lines = new ArrayList<>();
        if (program == null) {
            return lines;
        }

        try {
            GraphRootSelection selection = selectCallGraphRoots(program, Collections.emptyMap());
            if (selection.error != null && !selection.error.isEmpty()) {
                warnings.add("Root function selection reported: " + selection.error);
            }
            for (Function root : selection.roots) {
                if (root == null || lines.size() >= maxItems) {
                    continue;
                }
                String strategy = selection.strategy != null && !selection.strategy.isEmpty()
                    ? " [" + selection.strategy + "]"
                    : "";
                lines.add(root.getName() + " @ " + root.getEntryPoint() + strategy);
            }
        } catch (Exception e) {
            warnings.add("Root function summary collection failed: " + safe(e.getMessage()));
        }
        return lines;
    }

    private GraphRootSelection selectCallGraphRoots(Program program, Map<String, String> qparams) {
        if (program == null) {
            return new GraphRootSelection(Collections.emptyList(), "unavailable", null);
        }

        String rootAddress = trimToNull(qparams.get("rootAddress"));
        if (rootAddress != null) {
            try {
                Address addr = program.getAddressFactory().getAddress(rootAddress);
                Function func = getFunctionForAddress(program, addr);
                if (func == null) {
                    return new GraphRootSelection(
                        Collections.emptyList(),
                        "explicit_address",
                        "No function found at or containing rootAddress " + rootAddress
                    );
                }
                return new GraphRootSelection(Collections.singletonList(func), "explicit_address", null);
            } catch (Exception e) {
                return new GraphRootSelection(
                    Collections.emptyList(),
                    "explicit_address",
                    "Invalid rootAddress " + rootAddress + ": " + e.getMessage()
                );
            }
        }

        String rootName = trimToNull(qparams.get("rootName"));
        if (rootName != null) {
            LinkedHashMap<String, Function> matches = new LinkedHashMap<>();
            for (Function func : program.getFunctionManager().getFunctions(true)) {
                if (rootName.equals(func.getName())) {
                    matches.put(func.getEntryPoint().toString(), func);
                }
            }
            if (matches.isEmpty()) {
                return new GraphRootSelection(
                    Collections.emptyList(),
                    "explicit_name",
                    "No function found with rootName " + rootName
                );
            }
            return new GraphRootSelection(new ArrayList<>(matches.values()), "explicit_name", null);
        }

        Function currentFunction = getCurrentFunctionObject();
        if (currentFunction != null) {
            return new GraphRootSelection(Collections.singletonList(currentFunction), "current_function", null);
        }

        return new GraphRootSelection(Collections.emptyList(), "heuristic", null);
    }

    private String trimToNull(String value) {
        if (value == null) {
            return null;
        }
        String trimmed = value.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }

    private boolean parseBooleanParam(String value, boolean defaultValue) {
        String normalized = trimToNull(value);
        if (normalized == null) {
            return defaultValue;
        }
        switch (normalized.toLowerCase(Locale.ROOT)) {
            case "1":
            case "true":
            case "yes":
            case "on":
                return true;
            case "0":
            case "false":
            case "no":
            case "off":
                return false;
            default:
                return defaultValue;
        }
    }

    private String normalizeProjectFolderPath(String rawPath) {
        String trimmed = trimToNull(rawPath);
        if (trimmed == null || "/".equals(trimmed)) {
            return "/";
        }
        String normalized = trimmed.replace('\\', '/');
        if (!normalized.startsWith("/")) {
            normalized = "/" + normalized;
        }
        while (normalized.contains("//")) {
            normalized = normalized.replace("//", "/");
        }
        if (normalized.length() > 1 && normalized.endsWith("/")) {
            normalized = normalized.substring(0, normalized.length() - 1);
        }
        return normalized;
    }

    private String getDefaultUnpackedProjectFolderPath(Program program) {
        String basePath = "/";
        try {
            if (program != null && program.getDomainFile() != null && program.getDomainFile().getParent() != null) {
                basePath = safe(program.getDomainFile().getParent().getPathname());
            }
        }
        catch (Exception ignored) {}

        String normalizedBase = normalizeProjectFolderPath(basePath);
        if ("/".equals(normalizedBase)) {
            return "/unpacked";
        }
        return normalizedBase + "/unpacked";
    }

    private DomainFolder ensureProjectFolder(Project project, Program program, String requestedPath)
            throws IOException, InvalidNameException {
        DomainFolder folder = project.getProjectData().getRootFolder();
        String normalizedPath = normalizeProjectFolderPath(
            trimToNull(requestedPath) != null ? requestedPath : getDefaultUnpackedProjectFolderPath(program)
        );
        if ("/".equals(normalizedPath)) {
            return folder;
        }
        String[] parts = normalizedPath.substring(1).split("/");
        for (String part : parts) {
            String trimmed = trimToNull(part);
            if (trimmed == null) {
                continue;
            }
            DomainFolder next = folder.getFolder(trimmed);
            if (next == null) {
                next = folder.createFolder(trimmed);
            }
            folder = next;
        }
        return folder;
    }

    private Program openDomainFileAsCurrent(DomainFile domainFile) throws InterruptedException, InvocationTargetException {
        if (domainFile == null) {
            return null;
        }
        ProgramManager pm = tool.getService(ProgramManager.class);
        if (pm == null) {
            return null;
        }
        final Program[] opened = new Program[1];
        SwingUtilities.invokeAndWait(() -> opened[0] = pm.openProgram(domainFile, ProgramManager.OPEN_CURRENT));
        return opened[0];
    }

    private String importExecutableIntoCurrentProject(
        String filePath,
        String projectFolderPath,
        boolean openImportedProgram,
        boolean reuseExisting
    ) {
        String candidatePath = trimToNull(filePath);
        if (candidatePath == null) {
            return jsonError("file_path is required");
        }

        File sourceFile = new File(candidatePath);
        if (!sourceFile.isFile()) {
            return jsonError("file_path does not resolve to an existing file: " + candidatePath);
        }

        Project project = AppInfo.getActiveProject();
        if (project == null) {
            return jsonError("No active Ghidra project is available for import.");
        }

        Program currentProgram = getCurrentProgram();
        MessageLog log = new MessageLog();

        try {
            DomainFolder targetFolder = ensureProjectFolder(project, currentProgram, projectFolderPath);
            String targetFolderPath = safe(targetFolder.getPathname());
            String importName = sourceFile.getName();
            DomainFile existing = targetFolder.getFile(importName);
            Program openedProgram = null;

            if (existing != null) {
                if (!reuseExisting) {
                    return jsonError(
                        "A project file already exists at " + safe(existing.getPathname()) +
                        ". Reuse it or choose a different target folder."
                    );
                }
                if (openImportedProgram) {
                    openedProgram = openDomainFileAsCurrent(existing);
                    if (openedProgram != null) {
                        maybeQueueAutoWorkflowTrigger(openedProgram);
                    }
                }
                return "{"
                    + "\"ok\":true,"
                    + "\"reused_existing\":true,"
                    + "\"project_folder\":" + jsonStr(targetFolderPath) + ","
                    + "\"imported_domain_file\":" + jsonStr(safe(existing.getPathname())) + ","
                    + "\"opened_as_current\":" + (openedProgram != null ? "true" : "false") + ","
                    + "\"log\":" + jsonStr(log.toString())
                    + "}";
            }

            DomainFile savedFile = null;
            try (LoadResults<Program> results = AutoImporter.importByUsingBestGuess(
                sourceFile,
                project,
                targetFolderPath,
                this,
                log,
                TaskMonitor.DUMMY
            )) {
                results.save(TaskMonitor.DUMMY);
                if (results.getPrimary() != null) {
                    try {
                        savedFile = results.getPrimary().getSavedDomainFile();
                    }
                    catch (Exception ignored) {}
                }
                if (savedFile == null) {
                    savedFile = targetFolder.getFile(importName);
                }
            }

            if (savedFile == null) {
                return jsonError("Import completed but no saved project file could be resolved. Log: " + log.toString());
            }

            if (openImportedProgram) {
                openedProgram = openDomainFileAsCurrent(savedFile);
                if (openedProgram != null) {
                    maybeQueueAutoWorkflowTrigger(openedProgram);
                }
            }

            return "{"
                + "\"ok\":true,"
                + "\"reused_existing\":false,"
                + "\"project_folder\":" + jsonStr(targetFolderPath) + ","
                + "\"imported_domain_file\":" + jsonStr(safe(savedFile.getPathname())) + ","
                + "\"opened_as_current\":" + (openedProgram != null ? "true" : "false") + ","
                + "\"log\":" + jsonStr(log.toString())
                + "}";
        }
        catch (Exception e) {
            Msg.error(this, "Failed to import executable into current project", e);
            return jsonError("Import failed: " + safe(e.getMessage()));
        }
    }

    // ----------------------------------------------------------------------------------
    // Logic for rename, decompile, etc.
    // ----------------------------------------------------------------------------------

    private String decompileFunctionByName(String name) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(program);
        for (Function func : program.getFunctionManager().getFunctions(true)) {
            if (func.getName().equals(name)) {
                DecompileResults result =
                    decomp.decompileFunction(func, 30, new ConsoleTaskMonitor());
                if (result != null && result.decompileCompleted()) {
                    return result.getDecompiledFunction().getC();
                } else {
                    return "Decompilation failed";
                }
            }
        }
        return "Function not found";
    }

    private boolean renameFunction(String oldName, String newName) {
        Program program = getCurrentProgram();
        if (program == null) return false;

        AtomicBoolean successFlag = new AtomicBoolean(false);
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Rename function via HTTP");
                try {
                    for (Function func : program.getFunctionManager().getFunctions(true)) {
                        if (func.getName().equals(oldName)) {
                            func.setName(newName, SourceType.USER_DEFINED);
                            successFlag.set(true);
                            break;
                        }
                    }
                }
                catch (Exception e) {
                    Msg.error(this, "Error renaming function", e);
                }
                finally {
                    successFlag.set(program.endTransaction(tx, successFlag.get()));
                }
            });
        }
        catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute rename on Swing thread", e);
        }
        return successFlag.get();
    }

    private void renameDataAtAddress(String addressStr, String newName) {
        Program program = getCurrentProgram();
        if (program == null) return;

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Rename data");
                try {
                    Address addr = program.getAddressFactory().getAddress(addressStr);
                    Listing listing = program.getListing();
                    Data data = listing.getDefinedDataAt(addr);
                    if (data != null) {
                        SymbolTable symTable = program.getSymbolTable();
                        Symbol symbol = symTable.getPrimarySymbol(addr);
                        if (symbol != null) {
                            symbol.setName(newName, SourceType.USER_DEFINED);
                        } else {
                            symTable.createLabel(addr, newName, SourceType.USER_DEFINED);
                        }
                    }
                }
                catch (Exception e) {
                    Msg.error(this, "Rename data error", e);
                }
                finally {
                    program.endTransaction(tx, true);
                }
            });
        }
        catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute rename data on Swing thread", e);
        }
    }

    private String renameVariableInFunction(String functionName, String oldVarName, String newVarName) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(program);

        Function func = null;
        for (Function f : program.getFunctionManager().getFunctions(true)) {
            if (f.getName().equals(functionName)) {
                func = f;
                break;
            }
        }

        if (func == null) {
            return "Function not found";
        }

        DecompileResults result = decomp.decompileFunction(func, 30, new ConsoleTaskMonitor());
        if (result == null || !result.decompileCompleted()) {
            return "Decompilation failed";
        }

        HighFunction highFunction = result.getHighFunction();
        if (highFunction == null) {
            return "Decompilation failed (no high function)";
        }

        LocalSymbolMap localSymbolMap = highFunction.getLocalSymbolMap();
        if (localSymbolMap == null) {
            return "Decompilation failed (no local symbol map)";
        }

        HighSymbol highSymbol = null;
        Iterator<HighSymbol> symbols = localSymbolMap.getSymbols();
        while (symbols.hasNext()) {
            HighSymbol symbol = symbols.next();
            String symbolName = symbol.getName();
            
            if (symbolName.equals(oldVarName)) {
                highSymbol = symbol;
            }
            if (symbolName.equals(newVarName)) {
                return "Error: A variable with name '" + newVarName + "' already exists in this function";
            }
        }

        if (highSymbol == null) {
            return "Variable not found";
        }

        boolean commitRequired = checkFullCommit(highSymbol, highFunction);

        final HighSymbol finalHighSymbol = highSymbol;
        final Function finalFunction = func;
        AtomicBoolean successFlag = new AtomicBoolean(false);

        try {
            SwingUtilities.invokeAndWait(() -> {           
                int tx = program.startTransaction("Rename variable");
                try {
                    if (commitRequired) {
                        HighFunctionDBUtil.commitParamsToDatabase(highFunction, false,
                            ReturnCommitOption.NO_COMMIT, finalFunction.getSignatureSource());
                    }
                    HighFunctionDBUtil.updateDBVariable(
                        finalHighSymbol,
                        newVarName,
                        null,
                        SourceType.USER_DEFINED
                    );
                    successFlag.set(true);
                }
                catch (Exception e) {
                    Msg.error(this, "Failed to rename variable", e);
                }
                finally {
                    successFlag.set(program.endTransaction(tx, true));
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            String errorMsg = "Failed to execute rename on Swing thread: " + e.getMessage();
            Msg.error(this, errorMsg, e);
            return errorMsg;
        }
        return successFlag.get() ? "Variable renamed" : "Failed to rename variable";
    }

    /**
     * Copied from AbstractDecompilerAction.checkFullCommit, it's protected.
	 * Compare the given HighFunction's idea of the prototype with the Function's idea.
	 * Return true if there is a difference. If a specific symbol is being changed,
	 * it can be passed in to check whether or not the prototype is being affected.
	 * @param highSymbol (if not null) is the symbol being modified
	 * @param hfunction is the given HighFunction
	 * @return true if there is a difference (and a full commit is required)
	 */
	protected static boolean checkFullCommit(HighSymbol highSymbol, HighFunction hfunction) {
		if (highSymbol != null && !highSymbol.isParameter()) {
			return false;
		}
		Function function = hfunction.getFunction();
		Parameter[] parameters = function.getParameters();
		LocalSymbolMap localSymbolMap = hfunction.getLocalSymbolMap();
		int numParams = localSymbolMap.getNumParams();
		if (numParams != parameters.length) {
			return true;
		}

		for (int i = 0; i < numParams; i++) {
			HighSymbol param = localSymbolMap.getParamSymbol(i);
			if (param.getCategoryIndex() != i) {
				return true;
			}
			VariableStorage storage = param.getStorage();
			// Don't compare using the equals method so that DynamicVariableStorage can match
			if (0 != storage.compareTo(parameters[i].getVariableStorage())) {
				return true;
			}
		}

		return false;
	}

    // ----------------------------------------------------------------------------------
    // New methods to implement the new functionalities
    // ----------------------------------------------------------------------------------

    /**
     * Get function by address
     */
    private String getFunctionByAddress(String addressStr) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            Function func = program.getFunctionManager().getFunctionAt(addr);

            if (func == null) return "No function found at address " + addressStr;

            return String.format("Function: %s at %s\nSignature: %s\nEntry: %s\nBody: %s - %s",
                func.getName(),
                func.getEntryPoint(),
                func.getSignature(),
                func.getEntryPoint(),
                func.getBody().getMinAddress(),
                func.getBody().getMaxAddress());
        } catch (Exception e) {
            return "Error getting function: " + e.getMessage();
        }
    }

    /**
     * Get current address selected in Ghidra GUI
     */
    private String getCurrentAddress() {
        CodeViewerService service = tool.getService(CodeViewerService.class);
        if (service == null) return "Code viewer service not available";

        ProgramLocation location = getCurrentLocationObject();
        return (location != null) ? location.getAddress().toString() : "No current location";
    }

    /**
     * Get current function selected in Ghidra GUI
     */
    private String getCurrentFunction() {
        CodeViewerService service = tool.getService(CodeViewerService.class);
        if (service == null) return "Code viewer service not available";

        ProgramLocation location = getCurrentLocationObject();
        if (location == null) return "No current location";

        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        Function func = getCurrentFunctionObject(program, location);
        if (func == null) return "No function at current location: " + location.getAddress();

        return String.format("Function: %s at %s\nSignature: %s",
            func.getName(),
            func.getEntryPoint(),
            func.getSignature());
    }

    private ProgramLocation getCurrentLocationObject() {
        CodeViewerService service = tool.getService(CodeViewerService.class);
        return (service != null) ? service.getCurrentLocation() : null;
    }

    private Function getCurrentFunctionObject() {
        return getCurrentFunctionObject(getCurrentProgram(), getCurrentLocationObject());
    }

    private Function getCurrentFunctionObject(Program program, ProgramLocation location) {
        if (program == null || location == null || location.getAddress() == null) {
            return null;
        }
        return program.getFunctionManager().getFunctionContaining(location.getAddress());
    }

    /**
     * List all functions in the database
     */
    private String listFunctions() {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        StringBuilder result = new StringBuilder();
        for (Function func : program.getFunctionManager().getFunctions(true)) {
            result.append(String.format("%s at %s\n", 
                func.getName(), 
                func.getEntryPoint()));
        }

        return result.toString();
    }

    /**
     * Gets a function at the given address or containing the address
     * @return the function or null if not found
     */
    private Function getFunctionForAddress(Program program, Address addr) {
        Function func = program.getFunctionManager().getFunctionAt(addr);
        if (func == null) {
            func = program.getFunctionManager().getFunctionContaining(addr);
        }
        return func;
    }

    /**
     * Decompile a function at the given address
     */
    private String decompileFunctionByAddress(String addressStr) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            Function func = getFunctionForAddress(program, addr);
            if (func == null) return "No function found at or containing address " + addressStr;

            DecompInterface decomp = new DecompInterface();
            decomp.openProgram(program);
            DecompileResults result = decomp.decompileFunction(func, 30, new ConsoleTaskMonitor());

            return (result != null && result.decompileCompleted()) 
                ? result.getDecompiledFunction().getC() 
                : "Decompilation failed";
        } catch (Exception e) {
            return "Error decompiling function: " + e.getMessage();
        }
    }

    /**
     * Get assembly code for a function
     */
    private String disassembleFunction(String addressStr) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            Function func = getFunctionForAddress(program, addr);
            if (func == null) return "No function found at or containing address " + addressStr;

            StringBuilder result = new StringBuilder();
            Listing listing = program.getListing();
            Address start = func.getEntryPoint();
            Address end = func.getBody().getMaxAddress();

            InstructionIterator instructions = listing.getInstructions(start, true);
            while (instructions.hasNext()) {
                Instruction instr = instructions.next();
                if (instr.getAddress().compareTo(end) > 0) {
                    break; // Stop if we've gone past the end of the function
                }
                String comment = listing.getComment(CodeUnit.EOL_COMMENT, instr.getAddress());
                comment = (comment != null) ? "; " + comment : "";

                result.append(String.format("%s: %s %s\n", 
                    instr.getAddress(), 
                    instr.toString(),
                    comment));
            }

            return result.toString();
        } catch (Exception e) {
            return "Error disassembling function: " + e.getMessage();
        }
    }    

    /**
     * Set a comment using the specified comment type (PRE_COMMENT or EOL_COMMENT)
     */
    private boolean setCommentAtAddress(String addressStr, String comment, int commentType, String transactionName) {
        Program program = getCurrentProgram();
        if (program == null) return false;
        if (addressStr == null || addressStr.isEmpty() || comment == null) return false;

        AtomicBoolean success = new AtomicBoolean(false);

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction(transactionName);
                try {
                    Address addr = program.getAddressFactory().getAddress(addressStr);
                    program.getListing().setComment(addr, commentType, comment);
                    success.set(true);
                } catch (Exception e) {
                    Msg.error(this, "Error setting " + transactionName.toLowerCase(), e);
                } finally {
                    success.set(program.endTransaction(tx, success.get()));
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute " + transactionName.toLowerCase() + " on Swing thread", e);
        }

        return success.get();
    }

    /**
     * Set a comment for a given address in the function pseudocode
     */
    private boolean setDecompilerComment(String addressStr, String comment) {
        return setCommentAtAddress(addressStr, comment, CodeUnit.PRE_COMMENT, "Set decompiler comment");
    }

    /**
     * Set a comment for a given address in the function disassembly
     */
    private boolean setDisassemblyComment(String addressStr, String comment) {
        return setCommentAtAddress(addressStr, comment, CodeUnit.EOL_COMMENT, "Set disassembly comment");
    }

    /**
     * Class to hold the result of a prototype setting operation
     */
    private static class PrototypeResult {
        private final boolean success;
        private final String errorMessage;

        public PrototypeResult(boolean success, String errorMessage) {
            this.success = success;
            this.errorMessage = errorMessage;
        }

        public boolean isSuccess() {
            return success;
        }

        public String getErrorMessage() {
            return errorMessage;
        }
    }

    /**
     * Rename a function by its address
     */
    private boolean renameFunctionByAddress(String functionAddrStr, String newName) {
        Program program = getCurrentProgram();
        if (program == null) return false;
        if (functionAddrStr == null || functionAddrStr.isEmpty() || 
            newName == null || newName.isEmpty()) {
            return false;
        }

        AtomicBoolean success = new AtomicBoolean(false);

        try {
            SwingUtilities.invokeAndWait(() -> {
                performFunctionRename(program, functionAddrStr, newName, success);
            });
        } catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute rename function on Swing thread", e);
        }

        return success.get();
    }

    /**
     * Helper method to perform the actual function rename within a transaction
     */
    private void performFunctionRename(Program program, String functionAddrStr, String newName, AtomicBoolean success) {
        int tx = program.startTransaction("Rename function by address");
        try {
            Address addr = program.getAddressFactory().getAddress(functionAddrStr);
            Function func = getFunctionForAddress(program, addr);

            if (func == null) {
                Msg.error(this, "Could not find function at address: " + functionAddrStr);
                return;
            }

            func.setName(newName, SourceType.USER_DEFINED);
            success.set(true);
        } catch (Exception e) {
            Msg.error(this, "Error renaming function by address", e);
        } finally {
            program.endTransaction(tx, success.get());
        }
    }

    /**
     * Set a function's prototype with proper error handling using ApplyFunctionSignatureCmd
     */
    private PrototypeResult setFunctionPrototype(String functionAddrStr, String prototype) {
        // Input validation
        Program program = getCurrentProgram();
        if (program == null) return new PrototypeResult(false, "No program loaded");
        if (functionAddrStr == null || functionAddrStr.isEmpty()) {
            return new PrototypeResult(false, "Function address is required");
        }
        if (prototype == null || prototype.isEmpty()) {
            return new PrototypeResult(false, "Function prototype is required");
        }

        final StringBuilder errorMessage = new StringBuilder();
        final AtomicBoolean success = new AtomicBoolean(false);

        try {
            SwingUtilities.invokeAndWait(() -> 
                applyFunctionPrototype(program, functionAddrStr, prototype, success, errorMessage));
        } catch (InterruptedException | InvocationTargetException e) {
            String msg = "Failed to set function prototype on Swing thread: " + e.getMessage();
            errorMessage.append(msg);
            Msg.error(this, msg, e);
        }

        return new PrototypeResult(success.get(), errorMessage.toString());
    }

    /**
     * Helper method that applies the function prototype within a transaction
     */
    private void applyFunctionPrototype(Program program, String functionAddrStr, String prototype, 
                                       AtomicBoolean success, StringBuilder errorMessage) {
        try {
            // Get the address and function
            Address addr = program.getAddressFactory().getAddress(functionAddrStr);
            Function func = getFunctionForAddress(program, addr);

            if (func == null) {
                String msg = "Could not find function at address: " + functionAddrStr;
                errorMessage.append(msg);
                Msg.error(this, msg);
                return;
            }

            Msg.info(this, "Setting prototype for function " + func.getName() + ": " + prototype);

            // Store original prototype as a comment for reference
            addPrototypeComment(program, func, prototype);

            // Use ApplyFunctionSignatureCmd to parse and apply the signature
            parseFunctionSignatureAndApply(program, addr, prototype, success, errorMessage);

        } catch (Exception e) {
            String msg = "Error setting function prototype: " + e.getMessage();
            errorMessage.append(msg);
            Msg.error(this, msg, e);
        }
    }

    /**
     * Add a comment showing the prototype being set
     */
    private void addPrototypeComment(Program program, Function func, String prototype) {
        int txComment = program.startTransaction("Add prototype comment");
        try {
            program.getListing().setComment(
                func.getEntryPoint(), 
                CodeUnit.PLATE_COMMENT, 
                "Setting prototype: " + prototype
            );
        } finally {
            program.endTransaction(txComment, true);
        }
    }

    /**
     * Parse and apply the function signature with error handling
     */
    private void parseFunctionSignatureAndApply(Program program, Address addr, String prototype,
                                              AtomicBoolean success, StringBuilder errorMessage) {
        // Use ApplyFunctionSignatureCmd to parse and apply the signature
        int txProto = program.startTransaction("Set function prototype");
        try {
            // Get data type manager
            DataTypeManager dtm = program.getDataTypeManager();

            // Get data type manager service
            ghidra.app.services.DataTypeManagerService dtms = 
                tool.getService(ghidra.app.services.DataTypeManagerService.class);

            // Create function signature parser
            ghidra.app.util.parser.FunctionSignatureParser parser = 
                new ghidra.app.util.parser.FunctionSignatureParser(dtm, dtms);

            // Parse the prototype into a function signature
            ghidra.program.model.data.FunctionDefinitionDataType sig = parser.parse(null, prototype);

            if (sig == null) {
                String msg = "Failed to parse function prototype";
                errorMessage.append(msg);
                Msg.error(this, msg);
                return;
            }

            // Create and apply the command
            ghidra.app.cmd.function.ApplyFunctionSignatureCmd cmd = 
                new ghidra.app.cmd.function.ApplyFunctionSignatureCmd(
                    addr, sig, SourceType.USER_DEFINED);

            // Apply the command to the program
            boolean cmdResult = cmd.applyTo(program, new ConsoleTaskMonitor());

            if (cmdResult) {
                success.set(true);
                Msg.info(this, "Successfully applied function signature");
            } else {
                String msg = "Command failed: " + cmd.getStatusMsg();
                errorMessage.append(msg);
                Msg.error(this, msg);
            }
        } catch (Exception e) {
            String msg = "Error applying function signature: " + e.getMessage();
            errorMessage.append(msg);
            Msg.error(this, msg, e);
        } finally {
            program.endTransaction(txProto, success.get());
        }
    }

    /**
     * Set a local variable's type using HighFunctionDBUtil.updateDBVariable
     */
    private boolean setLocalVariableType(String functionAddrStr, String variableName, String newType) {
        // Input validation
        Program program = getCurrentProgram();
        if (program == null) return false;
        if (functionAddrStr == null || functionAddrStr.isEmpty() || 
            variableName == null || variableName.isEmpty() ||
            newType == null || newType.isEmpty()) {
            return false;
        }

        AtomicBoolean success = new AtomicBoolean(false);

        try {
            SwingUtilities.invokeAndWait(() -> 
                applyVariableType(program, functionAddrStr, variableName, newType, success));
        } catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute set variable type on Swing thread", e);
        }

        return success.get();
    }

    /**
     * Helper method that performs the actual variable type change
     */
    private void applyVariableType(Program program, String functionAddrStr, 
                                  String variableName, String newType, AtomicBoolean success) {
        try {
            // Find the function
            Address addr = program.getAddressFactory().getAddress(functionAddrStr);
            Function func = getFunctionForAddress(program, addr);

            if (func == null) {
                Msg.error(this, "Could not find function at address: " + functionAddrStr);
                return;
            }

            DecompileResults results = decompileFunction(func, program);
            if (results == null || !results.decompileCompleted()) {
                return;
            }

            ghidra.program.model.pcode.HighFunction highFunction = results.getHighFunction();
            if (highFunction == null) {
                Msg.error(this, "No high function available");
                return;
            }

            // Find the symbol by name
            HighSymbol symbol = findSymbolByName(highFunction, variableName);
            if (symbol == null) {
                Msg.error(this, "Could not find variable '" + variableName + "' in decompiled function");
                return;
            }

            // Get high variable
            HighVariable highVar = symbol.getHighVariable();
            if (highVar == null) {
                Msg.error(this, "No HighVariable found for symbol: " + variableName);
                return;
            }

            Msg.info(this, "Found high variable for: " + variableName + 
                     " with current type " + highVar.getDataType().getName());

            // Find the data type
            DataTypeManager dtm = program.getDataTypeManager();
            DataType dataType = resolveDataType(dtm, newType);

            if (dataType == null) {
                Msg.error(this, "Could not resolve data type: " + newType);
                return;
            }

            Msg.info(this, "Using data type: " + dataType.getName() + " for variable " + variableName);

            // Apply the type change in a transaction
            updateVariableType(program, symbol, dataType, success);

        } catch (Exception e) {
            Msg.error(this, "Error setting variable type: " + e.getMessage());
        }
    }

    /**
     * Find a high symbol by name in the given high function
     */
    private HighSymbol findSymbolByName(ghidra.program.model.pcode.HighFunction highFunction, String variableName) {
        Iterator<HighSymbol> symbols = highFunction.getLocalSymbolMap().getSymbols();
        while (symbols.hasNext()) {
            HighSymbol s = symbols.next();
            if (s.getName().equals(variableName)) {
                return s;
            }
        }
        return null;
    }

    /**
     * Decompile a function and return the results
     */
    private DecompileResults decompileFunction(Function func, Program program) {
        // Set up decompiler for accessing the decompiled function
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(program);
        decomp.setSimplificationStyle("decompile"); // Full decompilation

        // Decompile the function
        DecompileResults results = decomp.decompileFunction(func, 60, new ConsoleTaskMonitor());

        if (!results.decompileCompleted()) {
            Msg.error(this, "Could not decompile function: " + results.getErrorMessage());
            return null;
        }

        return results;
    }

    /**
     * Apply the type update in a transaction
     */
    private void updateVariableType(Program program, HighSymbol symbol, DataType dataType, AtomicBoolean success) {
        int tx = program.startTransaction("Set variable type");
        try {
            // Use HighFunctionDBUtil to update the variable with the new type
            HighFunctionDBUtil.updateDBVariable(
                symbol,                // The high symbol to modify
                symbol.getName(),      // Keep original name
                dataType,              // The new data type
                SourceType.USER_DEFINED // Mark as user-defined
            );

            success.set(true);
            Msg.info(this, "Successfully set variable type using HighFunctionDBUtil");
        } catch (Exception e) {
            Msg.error(this, "Error setting variable type: " + e.getMessage());
        } finally {
            program.endTransaction(tx, success.get());
        }
    }

    private String applyDataTypeToData(String addressStr, String dataTypeName) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        String normalizedAddress = trimToNull(addressStr);
        String normalizedTypeName = trimToNull(dataTypeName);
        if (normalizedAddress == null || normalizedTypeName == null) {
            return "Address and data_type_name are required";
        }

        StringBuilder message = new StringBuilder();
        AtomicBoolean success = new AtomicBoolean(false);
        try {
            SwingUtilities.invokeAndWait(() -> applyDataTypeToDataOnSwing(program, normalizedAddress, normalizedTypeName, success, message));
        } catch (InterruptedException | InvocationTargetException e) {
            return "Failed to execute apply_data_type_to_data on Swing thread: " + e.getMessage();
        }
        return success.get() ? "Data type applied successfully" : ("Failed to apply data type: " + message);
    }

    private void applyDataTypeToDataOnSwing(
        Program program,
        String addressStr,
        String dataTypeName,
        AtomicBoolean success,
        StringBuilder message
    ) {
        int tx = program.startTransaction("Apply data type to data");
        try {
            Address address = program.getAddressFactory().getAddress(addressStr);
            if (address == null) {
                message.append("Invalid address: ").append(addressStr);
                return;
            }

            DataType dataType = resolveDataTypeStrict(program.getDataTypeManager(), dataTypeName);
            if (dataType == null) {
                message.append("Could not resolve data type: ").append(dataTypeName);
                return;
            }

            Listing listing = program.getListing();
            int clearLen = Math.max(1, dataType.getLength());
            Address end = address;
            if (clearLen > 1) {
                end = address.add(clearLen - 1L);
            }
            listing.clearCodeUnits(address, end, false);
            listing.createData(address, dataType);
            success.set(true);
        } catch (Exception e) {
            message.append(e.getMessage());
            Msg.error(this, "Failed to apply data type to data: " + e.getMessage(), e);
        } finally {
            program.endTransaction(tx, success.get());
        }
    }

    private String createStructType(String typeName, String fieldsSpec, boolean replaceExisting) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        String normalizedTypeName = trimToNull(typeName);
        if (normalizedTypeName == null) {
            return "type_name is required";
        }

        List<StructFieldSpec> fields = parseStructFieldSpecs(fieldsSpec);
        if (fields.isEmpty()) {
            return "fields_spec must contain at least one field";
        }

        StringBuilder message = new StringBuilder();
        AtomicBoolean success = new AtomicBoolean(false);
        try {
            SwingUtilities.invokeAndWait(() ->
                createStructTypeOnSwing(program, normalizedTypeName, fields, replaceExisting, success, message)
            );
        } catch (InterruptedException | InvocationTargetException e) {
            return "Failed to execute create_struct_type on Swing thread: " + e.getMessage();
        }
        return success.get() ? "Struct type created successfully" : ("Failed to create struct type: " + message);
    }

    private void createStructTypeOnSwing(
        Program program,
        String typeName,
        List<StructFieldSpec> fields,
        boolean replaceExisting,
        AtomicBoolean success,
        StringBuilder message
    ) {
        int tx = program.startTransaction("Create struct type");
        try {
            DataTypeManager dtm = program.getDataTypeManager();
            CategoryPath categoryPath = new CategoryPath("/AgentQueue");
            StructureDataType structType = new StructureDataType(categoryPath, typeName, 0);

            for (StructFieldSpec field : fields) {
                DataType fieldType = resolveDataTypeStrict(dtm, field.typeName);
                if (fieldType == null) {
                    message.append("Unknown field type: ").append(field.typeName);
                    return;
                }
                DataType appliedType = fieldType;
                if (field.count > 1) {
                    int elementLength = Math.max(1, fieldType.getLength());
                    appliedType = new ArrayDataType(fieldType, field.count, elementLength);
                }
                structType.add(appliedType, field.name, field.comment);
            }

            dtm.addDataType(
                structType,
                replaceExisting ? DataTypeConflictHandler.REPLACE_HANDLER : DataTypeConflictHandler.DEFAULT_HANDLER
            );
            success.set(true);
        } catch (Exception e) {
            message.append(e.getMessage());
            Msg.error(this, "Failed to create struct type: " + e.getMessage(), e);
        } finally {
            program.endTransaction(tx, success.get());
        }
    }

    private String createEnumType(String typeName, String membersSpec, int byteSize, boolean replaceExisting) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        String normalizedTypeName = trimToNull(typeName);
        if (normalizedTypeName == null) {
            return "type_name is required";
        }

        List<EnumMemberSpec> members = parseEnumMemberSpecs(membersSpec);
        if (members.isEmpty()) {
            return "members_spec must contain at least one enum member";
        }

        int normalizedByteSize = Math.max(1, byteSize);
        StringBuilder message = new StringBuilder();
        AtomicBoolean success = new AtomicBoolean(false);
        try {
            SwingUtilities.invokeAndWait(() ->
                createEnumTypeOnSwing(program, normalizedTypeName, members, normalizedByteSize, replaceExisting, success, message)
            );
        } catch (InterruptedException | InvocationTargetException e) {
            return "Failed to execute create_enum_type on Swing thread: " + e.getMessage();
        }
        return success.get() ? "Enum type created successfully" : ("Failed to create enum type: " + message);
    }

    private void createEnumTypeOnSwing(
        Program program,
        String typeName,
        List<EnumMemberSpec> members,
        int byteSize,
        boolean replaceExisting,
        AtomicBoolean success,
        StringBuilder message
    ) {
        int tx = program.startTransaction("Create enum type");
        try {
            DataTypeManager dtm = program.getDataTypeManager();
            CategoryPath categoryPath = new CategoryPath("/AgentQueue");
            EnumDataType enumType = new EnumDataType(categoryPath, typeName, byteSize);
            for (EnumMemberSpec member : members) {
                enumType.add(member.name, member.value);
            }
            dtm.addDataType(
                enumType,
                replaceExisting ? DataTypeConflictHandler.REPLACE_HANDLER : DataTypeConflictHandler.DEFAULT_HANDLER
            );
            success.set(true);
        } catch (Exception e) {
            message.append(e.getMessage());
            Msg.error(this, "Failed to create enum type: " + e.getMessage(), e);
        } finally {
            program.endTransaction(tx, success.get());
        }
    }

    private List<StructFieldSpec> parseStructFieldSpecs(String fieldsSpec) {
        List<StructFieldSpec> fields = new ArrayList<>();
        String normalized = trimToNull(fieldsSpec);
        if (normalized == null) {
            return fields;
        }
        for (String rawLine : normalized.split("\\r?\\n")) {
            String line = rawLine == null ? "" : rawLine.trim();
            if (line.isEmpty()) {
                continue;
            }
            String[] parts = line.split("\\t", -1);
            String name = parts.length > 0 ? trimToNull(parts[0]) : null;
            String typeName = parts.length > 1 ? trimToNull(parts[1]) : null;
            int count = parts.length > 2 ? parseIntOrDefault(parts[2], 1) : 1;
            String comment = parts.length > 3 ? trimToNull(parts[3]) : null;
            if (name == null || typeName == null) {
                continue;
            }
            fields.add(new StructFieldSpec(name, typeName, count, comment));
        }
        return fields;
    }

    private List<EnumMemberSpec> parseEnumMemberSpecs(String membersSpec) {
        List<EnumMemberSpec> members = new ArrayList<>();
        String normalized = trimToNull(membersSpec);
        if (normalized == null) {
            return members;
        }
        for (String rawLine : normalized.split("\\r?\\n")) {
            String line = rawLine == null ? "" : rawLine.trim();
            if (line.isEmpty()) {
                continue;
            }
            String[] parts = line.split("\\t", -1);
            String name = parts.length > 0 ? trimToNull(parts[0]) : null;
            String valueText = parts.length > 1 ? trimToNull(parts[1]) : null;
            String comment = parts.length > 2 ? trimToNull(parts[2]) : null;
            if (name == null || valueText == null) {
                continue;
            }
            long value;
            try {
                value = Long.decode(valueText);
            } catch (NumberFormatException ignored) {
                value = parseIntOrDefault(valueText, 0);
            }
            members.add(new EnumMemberSpec(name, value, comment));
        }
        return members;
    }

    private DataType resolveDataTypeStrict(DataTypeManager dtm, String typeName) {
        String normalizedTypeName = trimToNull(typeName);
        if (normalizedTypeName == null) {
            return null;
        }

        DataType direct = findDataTypeByNameInAllCategories(dtm, normalizedTypeName);
        if (direct != null) {
            return direct;
        }

        if (normalizedTypeName.startsWith("P") && normalizedTypeName.length() > 1) {
            String baseTypeName = normalizedTypeName.substring(1);
            if ("VOID".equalsIgnoreCase(baseTypeName)) {
                DataType voidType = dtm.getDataType("/void");
                return voidType == null ? null : new PointerDataType(voidType);
            }
            DataType baseType = resolveDataTypeStrict(dtm, baseTypeName);
            return baseType == null ? null : new PointerDataType(baseType);
        }

        switch (normalizedTypeName.toLowerCase(Locale.ROOT)) {
            case "int":
            case "long":
                return dtm.getDataType("/int");
            case "uint":
            case "unsigned int":
            case "unsigned long":
            case "dword":
                return dtm.getDataType("/uint");
            case "short":
                return dtm.getDataType("/short");
            case "ushort":
            case "unsigned short":
            case "word":
                return dtm.getDataType("/ushort");
            case "char":
            case "byte":
                return dtm.getDataType("/char");
            case "uchar":
            case "unsigned char":
                return dtm.getDataType("/uchar");
            case "longlong":
            case "__int64":
                return dtm.getDataType("/longlong");
            case "ulonglong":
            case "unsigned __int64":
                return dtm.getDataType("/ulonglong");
            case "bool":
            case "boolean":
                return dtm.getDataType("/bool");
            case "void":
                return dtm.getDataType("/void");
            default:
                DataType directType = dtm.getDataType("/" + normalizedTypeName);
                return directType;
        }
    }

    /**
     * Get all references to a specific address (xref to)
     */
    private String getXrefsTo(String addressStr, int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            ReferenceManager refManager = program.getReferenceManager();
            
            ReferenceIterator refIter = refManager.getReferencesTo(addr);
            
            List<String> refs = new ArrayList<>();
            while (refIter.hasNext()) {
                Reference ref = refIter.next();
                Address fromAddr = ref.getFromAddress();
                RefType refType = ref.getReferenceType();
                
                Function fromFunc = program.getFunctionManager().getFunctionContaining(fromAddr);
                String funcInfo = (fromFunc != null) ? " in " + fromFunc.getName() : "";
                
                refs.add(String.format("From %s%s [%s]", fromAddr, funcInfo, refType.getName()));
            }
            
            return paginateList(refs, offset, limit);
        } catch (Exception e) {
            return "Error getting references to address: " + e.getMessage();
        }
    }

    /**
     * Get all references from a specific address (xref from)
     */
    private String getXrefsFrom(String addressStr, int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            ReferenceManager refManager = program.getReferenceManager();
            
            Reference[] references = refManager.getReferencesFrom(addr);
            
            List<String> refs = new ArrayList<>();
            for (Reference ref : references) {
                Address toAddr = ref.getToAddress();
                RefType refType = ref.getReferenceType();
                
                String targetInfo = "";
                Function toFunc = program.getFunctionManager().getFunctionAt(toAddr);
                if (toFunc != null) {
                    targetInfo = " to function " + toFunc.getName();
                } else {
                    Data data = program.getListing().getDataAt(toAddr);
                    if (data != null) {
                        targetInfo = " to data " + (data.getLabel() != null ? data.getLabel() : data.getPathName());
                    }
                }
                
                refs.add(String.format("To %s%s [%s]", toAddr, targetInfo, refType.getName()));
            }
            
            return paginateList(refs, offset, limit);
        } catch (Exception e) {
            return "Error getting references from address: " + e.getMessage();
        }
    }

    /**
     * Get all references to a specific function by name
     */
    private String getFunctionXrefs(String functionName, int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (functionName == null || functionName.isEmpty()) return "Function name is required";

        try {
            List<String> refs = new ArrayList<>();
            FunctionManager funcManager = program.getFunctionManager();
            for (Function function : funcManager.getFunctions(true)) {
                if (function.getName().equals(functionName)) {
                    Address entryPoint = function.getEntryPoint();
                    ReferenceIterator refIter = program.getReferenceManager().getReferencesTo(entryPoint);
                    
                    while (refIter.hasNext()) {
                        Reference ref = refIter.next();
                        Address fromAddr = ref.getFromAddress();
                        RefType refType = ref.getReferenceType();
                        
                        Function fromFunc = funcManager.getFunctionContaining(fromAddr);
                        String funcInfo = (fromFunc != null) ? " in " + fromFunc.getName() : "";
                        
                        refs.add(String.format("From %s%s [%s]", fromAddr, funcInfo, refType.getName()));
                    }
                }
            }
            
            if (refs.isEmpty()) {
                return "No references found to function: " + functionName;
            }
            
            return paginateList(refs, offset, limit);
        } catch (Exception e) {
            return "Error getting function references: " + e.getMessage();
        }
    }

/**
 * List all defined strings in the program with their addresses
 */
    private String listDefinedStrings(int offset, int limit, String filter) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        List<String> lines = new ArrayList<>();
        DataIterator dataIt = program.getListing().getDefinedData(true);
        
        while (dataIt.hasNext()) {
            Data data = dataIt.next();
            
            if (data != null && isStringData(data)) {
                String value = data.getValue() != null ? data.getValue().toString() : "";
                
                if (filter == null || value.toLowerCase().contains(filter.toLowerCase())) {
                    String escapedValue = escapeString(value);
                    lines.add(String.format("%s: \"%s\"", data.getAddress(), escapedValue));
                }
            }
        }
        
        return paginateList(lines, offset, limit);
    }

    /**
     * Check if the given data is a string type
     */
    private boolean isStringData(Data data) {
        if (data == null) return false;
        
        DataType dt = data.getDataType();
        String typeName = dt.getName().toLowerCase();
        return typeName.contains("string") || typeName.contains("char") || typeName.equals("unicode");
    }

    /**
     * Escape special characters in a string for display
     */
    private String escapeString(String input) {
        if (input == null) return "";
        
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < input.length(); i++) {
            char c = input.charAt(i);
            if (c >= 32 && c < 127) {
                sb.append(c);
            } else if (c == '\n') {
                sb.append("\\n");
            } else if (c == '\r') {
                sb.append("\\r");
            } else if (c == '\t') {
                sb.append("\\t");
            } else {
                sb.append(String.format("\\x%02x", (int)c & 0xFF));
            }
        }
        return sb.toString();
    }

    /**
     * Resolves a data type by name, handling common types and pointer types
     * @param dtm The data type manager
     * @param typeName The type name to resolve
     * @return The resolved DataType, or null if not found
     */
    private DataType resolveDataType(DataTypeManager dtm, String typeName) {
        // First try to find exact match in all categories
        DataType dataType = findDataTypeByNameInAllCategories(dtm, typeName);
        if (dataType != null) {
            Msg.info(this, "Found exact data type match: " + dataType.getPathName());
            return dataType;
        }

        // Check for Windows-style pointer types (PXXX)
        if (typeName.startsWith("P") && typeName.length() > 1) {
            String baseTypeName = typeName.substring(1);

            // Special case for PVOID
            if (baseTypeName.equals("VOID")) {
                return new PointerDataType(dtm.getDataType("/void"));
            }

            // Try to find the base type
            DataType baseType = findDataTypeByNameInAllCategories(dtm, baseTypeName);
            if (baseType != null) {
                return new PointerDataType(baseType);
            }

            Msg.warn(this, "Base type not found for " + typeName + ", defaulting to void*");
            return new PointerDataType(dtm.getDataType("/void"));
        }

        // Handle common built-in types
        switch (typeName.toLowerCase()) {
            case "int":
            case "long":
                return dtm.getDataType("/int");
            case "uint":
            case "unsigned int":
            case "unsigned long":
            case "dword":
                return dtm.getDataType("/uint");
            case "short":
                return dtm.getDataType("/short");
            case "ushort":
            case "unsigned short":
            case "word":
                return dtm.getDataType("/ushort");
            case "char":
            case "byte":
                return dtm.getDataType("/char");
            case "uchar":
            case "unsigned char":
                return dtm.getDataType("/uchar");
            case "longlong":
            case "__int64":
                return dtm.getDataType("/longlong");
            case "ulonglong":
            case "unsigned __int64":
                return dtm.getDataType("/ulonglong");
            case "bool":
            case "boolean":
                return dtm.getDataType("/bool");
            case "void":
                return dtm.getDataType("/void");
            default:
                // Try as a direct path
                DataType directType = dtm.getDataType("/" + typeName);
                if (directType != null) {
                    return directType;
                }

                // Fallback to int if we couldn't find it
                Msg.warn(this, "Unknown type: " + typeName + ", defaulting to int");
                return dtm.getDataType("/int");
        }
    }
    
    /**
     * Find a data type by name in all categories/folders of the data type manager
     * This searches through all categories rather than just the root
     */
    private DataType findDataTypeByNameInAllCategories(DataTypeManager dtm, String typeName) {
        // Try exact match first
        DataType result = searchByNameInAllCategories(dtm, typeName);
        if (result != null) {
            return result;
        }

        // Try lowercase
        return searchByNameInAllCategories(dtm, typeName.toLowerCase());
    }

    /**
     * Helper method to search for a data type by name in all categories
     */
    private DataType searchByNameInAllCategories(DataTypeManager dtm, String name) {
        // Get all data types from the manager
        Iterator<DataType> allTypes = dtm.getAllDataTypes();
        while (allTypes.hasNext()) {
            DataType dt = allTypes.next();
            // Check if the name matches exactly (case-sensitive) 
            if (dt.getName().equals(name)) {
                return dt;
            }
            // For case-insensitive, we want an exact match except for case
            if (dt.getName().equalsIgnoreCase(name)) {
                return dt;
            }
        }
        return null;
    }

    // ----------------------------------------------------------------------------------
    // Utility: parse query params, parse post params, pagination, etc.
    // ----------------------------------------------------------------------------------

    /**
     * Parse query parameters from the URL, e.g. ?offset=10&limit=100
     */
    private Map<String, String> parseQueryParams(HttpExchange exchange) {
        Map<String, String> result = new HashMap<>();
        String query = exchange.getRequestURI().getQuery(); // e.g. offset=10&limit=100
        if (query != null) {
            String[] pairs = query.split("&");
            for (String p : pairs) {
                String[] kv = p.split("=");
                if (kv.length == 2) {
                    // URL decode parameter values
                    try {
                        String key = URLDecoder.decode(kv[0], StandardCharsets.UTF_8);
                        String value = URLDecoder.decode(kv[1], StandardCharsets.UTF_8);
                        result.put(key, value);
                    } catch (Exception e) {
                        Msg.error(this, "Error decoding URL parameter", e);
                    }
                }
            }
        }
        return result;
    }

    /**
     * Parse post body form params, e.g. oldName=foo&newName=bar
     */
    private Map<String, String> parsePostParams(HttpExchange exchange) throws IOException {
        byte[] body = exchange.getRequestBody().readAllBytes();
        String bodyStr = new String(body, StandardCharsets.UTF_8);
        Map<String, String> params = new HashMap<>();
        for (String pair : bodyStr.split("&")) {
            String[] kv = pair.split("=");
            if (kv.length == 2) {
                // URL decode parameter values
                try {
                    String key = URLDecoder.decode(kv[0], StandardCharsets.UTF_8);
                    String value = URLDecoder.decode(kv[1], StandardCharsets.UTF_8);
                    params.put(key, value);
                } catch (Exception e) {
                    Msg.error(this, "Error decoding URL parameter", e);
                }
            }
        }
        return params;
    }

    /**
     * Convert a list of strings into one big newline-delimited string, applying offset & limit.
     */
    private String paginateList(List<String> items, int offset, int limit) {
        int start = Math.max(0, offset);
        int end   = Math.min(items.size(), offset + limit);

        if (start >= items.size()) {
            return ""; // no items in range
        }
        List<String> sub = items.subList(start, end);
        return String.join("\n", sub);
    }

    /**
     * Parse an integer from a string, or return defaultValue if null/invalid.
     */
    private int parseIntOrDefault(String val, int defaultValue) {
        if (val == null) return defaultValue;
        try {
            return Integer.parseInt(val);
        }
        catch (NumberFormatException e) {
            return defaultValue;
        }
    }

    /**
     * Escape non-ASCII chars to avoid potential decode issues.
     */
    private String escapeNonAscii(String input) {
        if (input == null) return "";
        StringBuilder sb = new StringBuilder();
        for (char c : input.toCharArray()) {
            if (c >= 32 && c < 127) {
                sb.append(c);
            }
            else {
                sb.append("\\x");
                sb.append(Integer.toHexString(c & 0xFF));
            }
        }
        return sb.toString();
    }

    public Program getCurrentProgram() {
        ProgramManager pm = tool.getService(ProgramManager.class);
        return pm != null ? pm.getCurrentProgram() : null;
    }

private void sendResponse(HttpExchange exchange, String response) throws IOException {
    byte[] bytes = response.getBytes(StandardCharsets.UTF_8);
    exchange.getResponseHeaders().set("Content-Type", "text/plain; charset=utf-8");
    exchange.sendResponseHeaders(200, bytes.length);
    OutputStream os = exchange.getResponseBody();
    try {
        os.write(bytes);
    } finally {
        os.close();
    }
}

private void sendJsonResponse(HttpExchange exchange, String json) throws IOException {
    byte[] bytes = json.getBytes(StandardCharsets.UTF_8);
    exchange.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
    exchange.sendResponseHeaders(200, bytes.length);
    OutputStream os = exchange.getResponseBody();
    try {
        os.write(bytes);
    } finally {
        os.close();
    }
}

private String jsonError(String message) {
    return "{\"error\":" + jsonStr(message) + "}";
}

private String jsonStrArray(List<String> values) {
    StringBuilder sb = new StringBuilder();
    sb.append("[");
    if (values != null) {
        for (int i = 0; i < values.size(); i++) {
            if (i > 0) {
                sb.append(",");
            }
            sb.append(jsonStr(values.get(i)));
        }
    }
    sb.append("]");
    return sb.toString();
}

private String jsonStr(String s) {
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
                    out.append(String.format("\\u%04x", (int) c));
                } else {
                    out.append(c);
                }
        }
    }
    out.append('"');
    return out.toString();
}


    @Override
    public void dispose() {
        if (server != null) {
            Msg.info(this, "Stopping GhidraMCP HTTP server...");
            server.stop(1); // Stop with a small delay (e.g., 1 second) for connections to finish
            server = null; // Nullify the reference
            Msg.info(this, "GhidraMCP HTTP server stopped.");
        }
        super.dispose();
    }
}
