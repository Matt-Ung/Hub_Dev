# Malware Analysis Hub — Testing & Experimental Plan

## 1. Purpose

This plan covers two concerns:

1. **Functional validation** — confirming the hub produces correct, evidence-grounded output across the test corpus.
2. **Experimental evaluation** — quantifying how different system variables (agent topology, pipeline configuration, prompting strategy, tool access, model selection) affect analysis quality. This supports thesis findings.

For a source-code-centric benchmark and rubric set, see `Testing/C_Source_Evaluation/README.md`.

---

## 2. System Overview (Current Architecture)

The hub is a multi-stage, multi-agent pipeline built on Pydantic AI + Gradio + MCP.

**Execution order:**
```
User query → Preflight → [Presweeps] → Planner → Parallel Workers → [Validators] → Reporter
```

**Key configurable variables:**
| Variable | Location | Options |
|---|---|---|
| Agent topology | `architecture_presets.json` | 8 presets (minimal → ghidra_editing) |
| Pipeline configuration | `pipeline_presets.json` | 4+ presets (with/without validators, presweeps) |
| Agent tool access | `agent_archetype_specs.json` | static / dynamic / tool_free |
| Prompting strategy | `agent_archetype_prompts.json`, `base_prompts.json` | role specializations, base instructions |
| Validator review level | UI / env `DEFAULT_VALIDATOR_REVIEW_LEVEL` | easy / default / intermediate / strict |
| Model selection | `agent_archetype_specs.json`, env | per-archetype model IDs |
| Parallelism | env `MAX_PARALLEL_WORKERS` | 1–N |
| Shell execution mode | UI / env `DEFAULT_SHELL_EXECUTION_MODE` | none / ask / full |

---

## 3. Test Sample Corpus

The corpus is split across two directories with different purposes:

- `Testing/Prototype_Test_Executables/` — original regression samples; primarily Windows PE targets for Ghidra-assisted analysis.
- `Testing/Experimental_Test_Executables/` — new samples stratified by difficulty; designed to cover the full MCP server surface.

### 3.1 Prototype Samples

Use these 8 primary samples from `Testing/Prototype_Test_Executables/` for pipeline regression and EXP-H runs.

| Sample | Primary techniques | Key expected evidence |
|---|---|---|
| `test.exe` | Branch-heavy control flow, switch/jump table | Structured branching, switch dispatch, execution path from input to output |
| `floss_test.exe` | Stack strings, XOR-decoded runtime strings | `cmd.exe /c whoami`, `https://example.com/api/v1/ping`, decoded `kernel32.dll` |
| `floss_test_stripped.exe` | Stripped symbols + stack/XOR strings | String recovery without relying on symbol names |
| `anti_debug_test.exe` | `IsDebuggerPresent`, `CheckRemoteDebuggerPresent`, timing probe | Named anti-debug APIs, timing-based probe logic |
| `winapi_behavior_test.exe` | `GetProcAddress`, dynamic resolution, mutex, URL, registry | `VirtualAlloc`/`VirtualFree`, `Global\\UpdaterMutex`, registry path, stack-built command |
| `control_flow_flattened_test.exe` | Dispatcher/state-machine flow, opaque predicates | Flattened dispatcher pattern, reconstructed execution path |
| `api_hash_resolver_test.exe` | API hashing, delayed import resolution | Hash-based lookup, resolved API association |
| `resource_blob_loader_test.exe` | Embedded blob, staged decode path | Payload container, decode routine, staged content |

For each primary sample, maintain both default-compiler and `_gcc.exe` variants.

### 3.2 Experimental Samples

8 new samples in `Testing/Experimental_Test_Executables/`, stratified by difficulty and designed to span the full MCP tool surface. Use these for EXP-I (difficulty sweep) and for MCP tool smoke tests.

**Easy (baseline validation):**

| Sample | Primary techniques | Key expected evidence |
|---|---|---|
| `basic_loops_test.exe` | For/while/do-while loops, integer arithmetic, function calls | Clean decompilation, loop structure, call graph; no obfuscation claims |
| `string_table_test.exe` | Global const strings, pointer table, index lookup | All strings recovered by stringmcp/FLOSS; no false encoding claims |

**Medium (realistic complexity):**

| Sample | Primary techniques | Key expected evidence |
|---|---|---|
| `callback_dispatch_test.exe` | Function pointer dispatch table, struct command descriptors, indirect calls, state machine | Dispatch table resolved, all 5 handlers identified, state transitions traced |
| `config_decoder_test.exe` | Single-byte XOR config blob, key=value parser, stack buffer | Decoded strings: `C:\ProgramData\agent\config.ini`, port `8443`, flag `persist=true` |

**Hard (analysis challenges):**

| Sample | Primary techniques | Key expected evidence |
|---|---|---|
| `multilayer_encode_test.exe` | Two-layer encoding (ROL + XOR), encoded C2 URLs / registry / shell commands, per-entry metadata | Both decode layers identified; recovered strings include `https://c2.example.net/beacon/checkin`, registry path, `schtasks` command |
| `hash_dispatch_test.exe` | DJB2 hash-based dispatch, stack-built command strings, dead/decoy hash entries | DJB2 algorithm identified; hashes `0x7C9C4733`, `0x7C967DAA`, etc. matched to `ping`/`exec`/`exfil`/`sleep` |
| `embedded_payload_test.exe` | Structured blob header/magic/checksum, per-record XOR keys, dead records, staged extraction | Magic `0x504C4F44`, checksum algorithm, decoded path/URL/config records; UPX variant exercices upxmcp |
| `anti_analysis_suite_test.exe` | Anti-debug APIs (stack strings), timing probe, env fingerprinting, rotating-key XOR config, dead code, misleading function name `update_display` | Anti-debug APIs named; misleading function name noted; dead code branch identified as unreachable; decrypted config string recovered |

See `Testing/Experimental_Test_Executables/SAMPLE_INDEX.md` for full MCP server coverage mapping and build notes.

---

## 4. Experimental Framework

### 4.1 Design Rationale

The hub exposes multiple independent variables that can be isolated by holding everything else constant. The approach is a **controlled factorial experiment** where one variable is swept per experiment series while all others are fixed to a documented baseline.

**Baseline configuration:**
| Variable | Baseline value |
|---|---|
| Architecture | `balanced` |
| Pipeline | `preflight_planner_workers_reporter` |
| Validator review level | `default` |
| Shell execution | `none` |
| Model | whatever `agent_archetype_specs.json` defaults to |
| MAX_PARALLEL_WORKERS | `2` |
| Sample | `winapi_behavior_test.exe` (most diverse technique set) |

Each experimental series is identified as `EXP-<letter>` below.

---

### 4.2 Experiment Series

#### EXP-A: Agent Topology

**Question:** Does adding more specialized agents improve report quality?

**Sweep:** Run each architecture preset against the same sample and query.

| Condition | Architecture |
|---|---|
| A1 | `minimal` |
| A2 | `balanced` (baseline) |
| A3 | `aws_collaboration` |
| A4 | `runtime_enriched` |
| A5 | `static_swarm` |
| A6 | `ghidra_focused` |
| A7 | `code_reconstruction` |
| A8 | `ghidra_editing` |

**Fixed:** Pipeline = `preflight_planner_workers_reporter`, Sample = `winapi_behavior_test.exe`

**Metrics to record:** QS (quality score), tool call count, execution time, token estimate, artifact count.

---

#### EXP-B: Pipeline Configuration (Validation Gate)

**Question:** Does adding a validation gate improve report accuracy at the cost of latency?

| Condition | Pipeline |
|---|---|
| B1 | `preflight_planner_workers_reporter` (no validators, baseline) |
| B2 | `preflight_planner_workers_validators_reporter` (single validator) |
| B3 | `preflight_planner_workers_dual_validators_reporter` (two validators) |
| B4 | `auto_triage` (presweeps + planner + workers + reporter) |

**Fixed:** Architecture = `balanced`, Sample = `winapi_behavior_test.exe`

**Additional metric:** gate approval rate, replan count.

---

#### EXP-C: Deterministic Presweeps

**Question:** Does pre-populating planner context with deterministic tool results improve work item targeting?

| Condition | Presweeps enabled |
|---|---|
| C1 | Off (baseline pipeline) |
| C2 | On (auto_triage pipeline) |

**Fixed:** Architecture = `balanced`, Sample = `floss_test.exe`

**Additional metric:** planner work-item relevance score, string recovery completeness.

---

#### EXP-D: Prompting Strategy (Validator Review Level)

**Question:** Does tightening the validator's evidence threshold reduce false claims?

| Condition | Validator review level |
|---|---|
| D1 | `easy` |
| D2 | `default` (baseline) |
| D3 | `intermediate` |
| D4 | `strict` |

**Fixed:** Architecture = `balanced`, Pipeline = `preflight_planner_workers_validators_reporter`, Sample = `anti_debug_test.exe`

**Additional metric:** false claim rate, gate rejection count, revision instruction length.

---

#### EXP-E: Subagent Tool Access

**Question:** Which tool subset contributes most to report quality?

Create modified architecture presets where specific tool domains are removed:

| Condition | Tool access change |
|---|---|
| E1 | Full static toolset (baseline) |
| E2 | Ghidra only (remove FLOSS, capa, strings, hashdb) |
| E3 | FLOSS + strings only (remove Ghidra, capa) |
| E4 | capa only |
| E5 | No tools (tool_free workers, reporter-only synthesis) |

**Fixed:** Architecture = `balanced`, Pipeline = `preflight_planner_workers_reporter`, Sample = `floss_test.exe`

**Additional metric:** tool call distribution, coverage per tool class.

---

#### EXP-F: Model Selection

**Question:** Does using a stronger model for complex analyst roles improve output quality?

| Condition | Model assignment |
|---|---|
| F1 | All roles: weaker/faster model |
| F2 | All roles: default model (baseline) |
| F3 | Complex roles (control_flow, ghidra, c_reconstruction): stronger model |
| F4 | All roles: strongest available model |

**Fixed:** Architecture = `balanced`, Pipeline = `preflight_planner_workers_reporters`, Sample = `control_flow_flattened_test.exe`

**Additional metric:** token cost, execution time, specificity score.

---

#### EXP-G: Parallelism (Worker Concurrency)

**Question:** Does concurrency affect result quality (beyond speed)?

| Condition | MAX_PARALLEL_WORKERS |
|---|---|
| G1 | 1 (fully sequential) |
| G2 | 2 (baseline) |
| G3 | 4 |

**Fixed:** Architecture = `aws_collaboration` (6 workers), Pipeline = `preflight_planner_workers_reporter`, Sample = `winapi_behavior_test.exe`

**Note:** With 6 workers and MAX_PARALLEL_WORKERS=1 you stress-test sequential correctness. With 4 you stress-test concurrency and tool result caching.

---

#### EXP-H: Prototype Sample Regression

**Question:** Does the baseline configuration maintain quality across the full prototype corpus?

Run the baseline configuration against all 8 prototype samples (and their `_gcc.exe` variants). This is the primary regression suite.

**All 8 samples × 2 compiler variants = 16 runs.**

---

#### EXP-I: Experimental Corpus Difficulty Sweep

**Question:** Does analysis quality degrade predictably as sample complexity increases from easy to hard?

Run the baseline configuration against all 8 experimental samples.

| Condition | Sample | Difficulty | Expected QS range |
|---|---|---|---|
| I1 | `basic_loops_test.exe` | Easy | 20–25 |
| I2 | `string_table_test.exe` | Easy | 20–25 |
| I3 | `callback_dispatch_test.exe` | Medium | 15–22 |
| I4 | `config_decoder_test.exe` | Medium | 15–22 |
| I5 | `multilayer_encode_test.exe` | Hard | 10–20 |
| I6 | `hash_dispatch_test.exe` | Hard | 10–20 |
| I7 | `embedded_payload_test.exe` | Hard | 10–20 |
| I8 | `anti_analysis_suite_test.exe` | Hard | 10–20 |

**Fixed:** Architecture = `balanced`, Pipeline = `preflight_planner_workers_reporter`

**Additional metric:** QS gap between easy and hard conditions (a smaller gap suggests the pipeline handles complexity gracefully).

This series also serves as a **MCP tool coverage audit**: each hard sample is designed to exercise tools not covered by the prototype corpus (binwalk, hashdb, YARA). Record which tools were actually invoked per condition and compare against the expected tool mapping in `SAMPLE_INDEX.md`.

---

### 4.3 Replication

Run each condition **3 times** minimum. LLM outputs are stochastic; a single run is insufficient for comparison. Report mean ± standard deviation for each numeric metric.

For EXP-H (regression suite), 2 runs per condition is acceptable given the large matrix.

---

## 5. Scoring Rubric

Every run is scored on the following dimensions. Scores are assigned by the analyst reviewing the final report.

### 5.1 Dimensions

**A. Evidence Grounding (0–5)**
Does every claim cite a specific artifact?
- 5: All claims paired with named function, address, API, decoded string, or capa rule
- 4: Most claims cited; 1–2 unsupported assertions
- 3: Roughly half cited; some generic statements
- 2: More generic than specific
- 1: Mostly boilerplate with a few real artifacts
- 0: No evidence; pure speculation

**B. Specificity (0–5)**
Are technical details named rather than described vaguely?
- 5: Function names, API names, exact strings, addresses, struct names appear throughout
- 4: Most key details named; occasional vague phrase
- 3: Mix of named and vague
- 2: Few names; mostly "the function" / "a routine"
- 1: Almost entirely vague
- 0: No technical specifics at all

**C. Technique Coverage (0–5)**
Does the report address the sample's primary techniques?
- 5: All primary techniques identified and explained
- 4: All identified; 1 inadequately explained
- 3: Most identified; 1 missed entirely
- 2: Half identified
- 1: Only superficial identification
- 0: Primary techniques missed or wrong

**D. False Claim Penalty (0–5, higher = fewer false claims)**
Are there claims that contradict the sample's actual behavior or cite non-existent artifacts?
- 5: No false claims
- 4: 1 minor inaccuracy
- 3: 2–3 inaccuracies, or 1 significant error
- 2: Several errors
- 1: Many errors
- 0: Report is predominantly incorrect

**E. Planner Targeting (0–3)**
Were work items specific and well-targeted to the sample's techniques? (Evaluated from planner output, not available for tool_free conditions.)
- 3: Work items directly correspond to expected techniques; no filler tasks
- 2: Most items relevant; 1–2 generic tasks
- 1: Many generic or misaligned tasks
- 0: Planner output is generic boilerplate

**F. Report Conciseness (0–2)**
Is the report free of PE boilerplate, redundant preamble, and duplicate findings?
- 2: Tight, analyst-relevant output only
- 1: Some filler but core content is good
- 0: Heavy boilerplate dominates

**Total Quality Score (QS): 0–25**

---

### 5.2 Efficiency Metrics (recorded from tool logs)

| Metric | Source | Formula |
|---|---|---|
| Tool calls total | `logs/*/stage.log` | Count of `tool_call` events |
| Cache hit rate | `logs/*/stage.log` | `tool_cache_hit / (tool_call + tool_cache_hit)` |
| Unique tools used | `logs/*/stage.log` | Distinct `(server_id, tool_name)` pairs |
| Artifacts cited in report | Manual count | Named functions/APIs/strings in final report |
| Artifacts per tool call | Derived | `artifacts_cited / tool_calls_total` |
| Gate approval (first pass) | Validator output | Boolean |
| Replan count | Pipeline state | Integer |
| Execution time (s) | `pipeline_stage_progress` | `finished_at - started_at` summed across stages |
| Estimated token cost | Model logs / API response | Input + output tokens per stage |

---

### 5.3 Scoring Procedure

1. Complete the run. Save the final report text and tool log files.
2. Read the final report. Score dimensions A–F using the rubric above.
3. Count artifact citations (named functions, APIs, strings, addresses) in the final report.
4. Parse tool logs for efficiency metrics.
5. Enter all scores and metrics in the results spreadsheet (see Section 7).

---

## 6. Functional Acceptance Criteria

The following must hold for any run to be considered passing, regardless of experimental condition.

### Sample-specific criteria

**`test.exe`:**
- Identifies structured branching / switch-based dispatch
- Describes main execution path from input to output
- Does not label normal control flow as obfuscation

**`floss_test.exe`:**
- Recovers stack string content
- Identifies XOR-decoded string behavior
- Uses recovered string evidence in the final report

**`floss_test_stripped.exe`:**
- Produces useful findings without relying on symbol names
- Does not claim "packed/obfuscated" without supporting evidence

**`anti_debug_test.exe`:**
- Names `IsDebuggerPresent`
- Names `CheckRemoteDebuggerPresent`
- Mentions timing-based probe logic

**`winapi_behavior_test.exe`:**
- Identifies dynamic API resolution via `GetProcAddress`
- Names `VirtualAlloc` and `VirtualFree` as resolved
- Mentions `Global\\UpdaterMutex`
- Mentions the registry path and stack-built command string

**`control_flow_flattened_test.exe`:**
- Identifies dispatcher/state variable logic
- Reconstructs at least one real execution path through the flattened routine

**`api_hash_resolver_test.exe`:**
- Identifies hashing or export-parsing logic
- Associates the resolver with recovered APIs

**`resource_blob_loader_test.exe`:**
- Identifies the embedded blob/resource container
- Explains the decode/staging routine and its purpose

### 6.2 Experimental Sample Acceptance Criteria

**`basic_loops_test.exe`:**
- Reconstructs loop structure (for, while, do-while) without calling any control flow "obfuscated"
- Identifies call graph: `main` → `compute_sum`, `classify_value`, `accumulate`
- QS ≥ 20 required; lower scores indicate a tool integration or baseline issue

**`string_table_test.exe`:**
- Recovers all 8 message table strings and both status strings
- Identifies the pointer table structure in .rdata
- No false claims about encoding; QS ≥ 20 required

**`callback_dispatch_test.exe`:**
- Identifies the `COMMAND_TABLE` function pointer array
- Names all 5 handler functions (`cmd_init`, `cmd_load`, `cmd_transform`, `cmd_validate`, `cmd_finalize`)
- Explains the indirect call dispatch and state transitions (IDLE → RUNNING → DONE/ERROR)

**`config_decoder_test.exe`:**
- Recovers decoded config values: path `C:\ProgramData\agent\config.ini`, port `8443`, flag `persist=true`
- Identifies the XOR key (`0x4B`) and the decode loop
- Describes the key=value parser as a distinct analysis target

**`multilayer_encode_test.exe`:**
- Identifies both encoding layers (ROL and XOR) in the decode routine
- Recovers at least 2 of the 4 encoded strings (C2 URL, registry path, shell command, temp path)
- Does not claim single-pass XOR is the only layer

**`hash_dispatch_test.exe`:**
- Identifies the DJB2 hash algorithm (seed 5381, multiplier 33)
- Associates at least 2 hash constants with their command strings (`ping`, `exec`, `exfil`, `sleep`)
- Notes the dead/decoy entries as unreachable dispatch paths

**`embedded_payload_test.exe`:**
- Identifies magic constant `0x504C4F44` as a blob header marker
- Describes the rolling checksum algorithm
- Recovers at least 2 decoded records (PATH, URL, or CONFIG)
- Notes dead/padding records (type `0xFF`)

**`anti_analysis_suite_test.exe`:**
- Flags `update_display` as performing debugger detection despite the misleading name
- Names `IsDebuggerPresent` and `CheckRemoteDebuggerPresent` as detected via stack string recovery
- Identifies the `opaque_false` predicate as guarding dead code
- Recovers the rotating-key XOR config string (`c2=https://update.example.net/api;...`)

---

## 7. Results Tracking

### 7.1 Per-Run Record

For each run, record:

```
Run ID:         EXP-<letter><condition>-<sample>-<rep>   e.g. EXP-A2-winapi-1
Date:
Architecture:
Pipeline:
Validator level:
Shell mode:
Model:
Sample:
Compiler variant:

Scores:
  A (evidence grounding):    /5
  B (specificity):           /5
  C (technique coverage):    /5
  D (false claim penalty):   /5
  E (planner targeting):     /3
  F (conciseness):           /2
  QS (total):                /25

Efficiency:
  tool_calls_total:
  cache_hit_rate:
  unique_tools_used:
  artifacts_cited:
  artifacts_per_tool_call:
  gate_approved_first_pass:  yes/no/n/a
  replan_count:
  execution_time_s:
  estimated_tokens:

Notes (failures, unexpected behavior, tool errors):
```

### 7.2 Comparison Table Format

When summarizing a series (e.g., EXP-A), aggregate by condition:

| Condition | Architecture | QS mean | QS std | tool_calls | cache_hit% | artifacts | exec_s |
|---|---|---|---|---|---|---|---|
| A1 | minimal | | | | | | |
| A2 | balanced | | | | | | |
| ... | | | | | | | |

---

## 8. Test Execution Phases

### Phase 1: Build Verification

```bash
# Prototype samples
make -C Testing/Prototype_Test_Executables all-with-gcc

# Experimental samples
make -C Testing/Experimental_Test_Executables all-with-gcc

# Optional: UPX-packed variant for upxmcp testing
make -C Testing/Experimental_Test_Executables upx
```

Confirm: all prototype executables + `_gcc.exe` variants present; all 8 experimental executables + `_gcc.exe` variants present.

### Phase 2: MCP Tool Smoke Tests

For `floss_test.exe` and `winapi_behavior_test.exe` (prototype), verify each MCP tool individually:
- Ghidra: `get_program_info`, `list_functions`, `decompile_function`, `get_xrefs`
- FLOSS: string extraction with stack and decoded string output
- capa: compact JSON output with rule matches
- hashdb: lookup on any hash-like strings

For the experimental samples, run targeted smoke tests by tool:
- **stringmcp / flareflossmcp**: `string_table_test.exe` (all strings cleartext); `config_decoder_test.exe` (XOR-decoded config)
- **hashdbmcp**: `hash_dispatch_test.exe` (DJB2 hashes `0x7C9C4733`, etc.)
- **binwalkmcp**: `embedded_payload_test.exe` (magic `0x504C4F44`)
- **upxmcp**: `embedded_payload_test_upx.exe` (requires `make upx` first)
- **yaramcp**: `multilayer_encode_test.exe`, `anti_analysis_suite_test.exe`
- **CapaMCP**: any of the hard experimental samples

Confirm: all tools work with both no-space and spaced paths.

### Phase 3: Baseline Regression (EXP-H)

Run all 8 prototype samples × 2 compiler variants against the baseline configuration. Verify all sample-specific acceptance criteria pass.

### Phase 4: Experimental Series

Run each EXP series in order (A through G), 3 reps per condition. Record all metrics.

### Phase 5: Cross-Platform Regression

After any significant prompt or pipeline change:
- Windows native, no-space path
- Windows native, spaced path
- macOS host + Windows VM workflow (if applicable)

### Phase 6: Automation Trigger Smoke Test

If `AUTOMATION_TRIGGER_ENABLED=true`, verify:
- `POST /automation/ghidra-load` accepts valid payload and spawns analysis
- `GET /automation/health` returns 200
- `GET /automation/status` returns HTML panel
- Allow-list validation blocks unregistered program keys

---

## 9. Path and Platform Coverage

| Scenario | Path style | Required checks |
|---|---|---|
| Windows, no-space path | `C:\Samples\test.exe` | All tools succeed, orchestration completes |
| Windows, spaced path | `C:\Users\Analyst\Desktop\Hub Test Space\test.exe` | FLOSS, capa succeed; agent quotes path correctly |
| Windows, GCC variants | spaced path | Consistent output across default and `_gcc.exe` |
| macOS host + Windows VM | UNC or mapped drive with spaces | Tools handle path or fail with actionable error |

---

## 10. Run Cadence

| Trigger | Action |
|---|---|
| MCP wrapper change | Smoke test FLOSS + Ghidra on `floss_test.exe`, `winapi_behavior_test.exe`; targeted smoke test on the relevant experimental sample (see Phase 2) |
| Prompt/archetype change | Run full EXP-H prototype regression suite |
| Pipeline/orchestration change | Run EXP-B conditions |
| New experimental sample added | Run EXP-I on the full experimental corpus with baseline config |
| Pre-thesis chapter / milestone | Run all EXP series (A–I), record in results spreadsheet |
| Demo prep | Full prototype regression on Windows native + spaced path; EXP-I on experimental corpus |

---

## 11. Notes on Statistical Interpretation

- **QS variance within a condition** indicates output stochasticity. If std > 3, the condition is unreliable.
- **QS improvement between conditions** should exceed 2 points to be considered meaningful (given 3-rep variance).
- **Tool call count changes** can reflect efficiency gains (fewer calls, same QS) or coverage changes (more calls, higher QS).
- **Cache hit rate** is primarily an efficiency signal, not a quality signal, unless the rate is 0 (no reuse).
- **Gate rejection** in EXP-D is a quality signal only if the rejected claims would have lowered QS; record what was rejected.
- Compiler variant differences (default vs `_gcc.exe`) should produce QS within ±1. Larger gaps indicate the system is overfitting to compiler fingerprints.
