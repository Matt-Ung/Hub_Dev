from __future__ import annotations

import argparse
import json
import re
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List


ROOT = Path(__file__).resolve().parent
REPO_ROOT = ROOT.parents[1]
DATASETS_ROOT = ROOT / "datasets"


CORPORA = {
    "prototype": {
        "source_dir": REPO_ROOT / "Testing" / "Prototype_Test_Source",
        "manifest_path": REPO_ROOT / "Testing" / "Prototype_Test_Source" / "sample_manifest.json",
    },
    "experimental": {
        "source_dir": REPO_ROOT / "Testing" / "Experimental_Test_Source",
        "manifest_path": REPO_ROOT / "Testing" / "Experimental_Test_Source" / "sample_manifest.json",
    },
}


SPECIAL_SAMPLE_SOURCE_MAP = {
    "floss_test_02": "floss_test",
    "floss_test_stripped": "floss_test",
    "test_easy_stripped": "test",
    "test_easy_upx": "test",
    "anti_debug_medium_stripped": "anti_debug_test",
    "anti_debug_medium_upx": "anti_debug_test",
    "resource_blob_loader_hard_stripped": "resource_blob_loader_test",
    "resource_blob_loader_hard_upx": "resource_blob_loader_test",
    "embedded_payload_test_upx": "embedded_payload_test",
    "config_decoder_test_stripped": "config_decoder_test",
    "config_decoder_test_upx_stripped": "config_decoder_test",
    "maintenance_orchestrator_test_stripped": "maintenance_orchestrator_test",
    "hash_dispatch_test_stripped": "hash_dispatch_test",
    "branch_weave_snapshot_test_stripped": "branch_weave_snapshot_test",
}


DOMAIN_OVERRIDES = {
    "test": "algorithmic",
    "basic_loops_test": "algorithmic",
    "floss_test": "string_processing",
    "maintenance_orchestrator_test": "systems",
    "config_decoder_test": "file_processing",
    "signal_router_report_test": "systems",
    "stack_notice_scheduler_test": "systems",
    "embedded_payload_test": "file_processing",
    "resource_blob_loader_test": "file_processing",
    "callback_dispatch_test": "systems",
    "anti_debug_test": "systems",
    "anti_analysis_suite_test": "systems",
    "branch_weave_snapshot_test": "systems",
    "winapi_behavior_test": "systems",
    "control_flow_flattened_test": "systems",
    "api_hash_resolver_test": "systems",
    "multilayer_encode_test": "systems",
    "hash_dispatch_test": "systems",
}


TASK_NAME_MAP = {
    "T1": "program_behavior_summary",
    "T2": "goal_spec_inference",
    "T3": "function_io_side_effect_map",
    "T4": "control_data_flow_explanation",
    "T5": "partial_context_reconstruction",
    "T6": "pseudocode_structured_explanation",
    "T7": "bug_risk_detection",
    "T9": "intent_mapping",
    "T10": "test_input_synthesis",
}


TASK_OUTPUTS = {
    "T1": ["behavior_summary.md"],
    "T2": ["goal_inference.txt"],
    "T3": ["program_map.md"],
    "T4": ["control_flow_report.md"],
    "T5": ["partial_reconstruction.md"],
    "T6": ["pseudocode.md"],
    "T7": ["bug_review.md"],
    "T9": ["intent_map.md"],
    "T10": ["test_plan.md"],
}


TASK_PROMPTS = {task_id: f"c_source_eval_v1:{task_id}" for task_id in TASK_NAME_MAP}


TASK_METRICS = {
    "T1": {
        "semantic_correctness": 30,
        "completeness": 20,
        "precision": 10,
        "hallucination_control": 15,
        "source_consistency": 15,
        "clarity_usefulness": 10,
    },
    "T2": {
        "goal_spec_accuracy": 35,
        "semantic_correctness": 20,
        "precision": 10,
        "hallucination_control": 15,
        "source_consistency": 10,
        "clarity_usefulness": 10,
    },
    "T3": {
        "function_coverage": 20,
        "input_output_coverage": 20,
        "side_effect_coverage": 20,
        "precision": 10,
        "hallucination_control": 15,
        "clarity_usefulness": 15,
    },
    "T4": {
        "control_flow_accuracy": 25,
        "data_flow_accuracy": 25,
        "completeness": 15,
        "hallucination_control": 15,
        "source_consistency": 10,
        "clarity_usefulness": 10,
    },
    "T5": {
        "reconstruction_fidelity": 30,
        "uncertainty_calibration": 20,
        "precision": 15,
        "hallucination_control": 20,
        "clarity_usefulness": 15,
    },
    "T6": {
        "semantic_correctness": 30,
        "control_flow_accuracy": 20,
        "completeness": 15,
        "hallucination_control": 15,
        "source_consistency": 10,
        "clarity_usefulness": 10,
    },
    "T7": {
        "risk_assessment_accuracy": 30,
        "false_positive_control": 20,
        "severity_prioritization": 15,
        "precision": 10,
        "source_consistency": 15,
        "clarity_usefulness": 10,
    },
    "T9": {
        "intent_alignment": 35,
        "semantic_correctness": 20,
        "completeness": 15,
        "hallucination_control": 15,
        "source_consistency": 5,
        "clarity_usefulness": 10,
    },
    "T10": {
        "completeness": 20,
        "precision": 20,
        "semantic_correctness": 15,
        "hallucination_control": 15,
        "source_consistency": 10,
        "clarity_usefulness": 20,
    },
}


TASK_PASS_THRESHOLDS = {
    "T1": {"task_score_min": 70, "min_metric_scores": {"semantic_correctness": 3, "hallucination_control": 3}},
    "T2": {"task_score_min": 70, "min_metric_scores": {"goal_spec_accuracy": 3, "hallucination_control": 3}},
    "T3": {"task_score_min": 70, "min_metric_scores": {"function_coverage": 3, "side_effect_coverage": 2}},
    "T4": {"task_score_min": 70, "min_metric_scores": {"control_flow_accuracy": 3, "data_flow_accuracy": 3}},
    "T5": {"task_score_min": 70, "min_metric_scores": {"reconstruction_fidelity": 3, "uncertainty_calibration": 3}},
    "T6": {"task_score_min": 70, "min_metric_scores": {"semantic_correctness": 3, "control_flow_accuracy": 3}},
    "T7": {"task_score_min": 70, "min_metric_scores": {"risk_assessment_accuracy": 3, "false_positive_control": 3}},
    "T9": {"task_score_min": 70, "min_metric_scores": {"intent_alignment": 3, "semantic_correctness": 3}},
    "T10": {"task_score_min": 70, "min_metric_scores": {"completeness": 3, "precision": 3}},
}


REFERENCE_OVERRIDES: Dict[str, Dict[str, Any]] = {
    "basic_loops_test": {
        "reference_status": "reviewed_concrete_anchor_v1",
        "goal_summary": (
            "This baseline sample computes the sum 1..N, classifies that result into buckets, "
            "accumulates an integer array until a -1 sentinel is seen, and then runs a countdown loop."
        ),
        "primary_behaviors": [
            "compute_sum performs a simple 1..N summation loop",
            "classify_value maps totals into -1/0/1/2/3 via an if/else ladder",
            "accumulate stops early when it encounters the sentinel value -1",
            "main calls compute_sum, classify_value, accumulate, and then a separate countdown while-loop",
        ],
        "expected_findings": [
            "Call graph: main -> compute_sum, classify_value, accumulate",
            "The sample array is {5, 10, 15, -1, 99, 200} and accumulate should stop at -1",
            "If argc > 1 then base=20, otherwise base=10",
            "No encoding, packing, or anti-analysis behavior should be claimed",
        ],
        "gold_facts": [
            "compute_sum uses a for-loop from i=1 through i<=n and returns the arithmetic total",
            "classify_value returns -1 for negative, 0 for zero, 1 for <100, 2 for <1000, else 3",
            "accumulate uses a do-while loop and breaks when arr[idx] == -1",
            "main prints marker:basic_loops_baseline before exiting",
        ],
    },
    "maintenance_orchestrator_test": {
        "reference_status": "reviewed_concrete_anchor_v1",
        "goal_summary": (
            "This deceptive-surface sample decodes a fixed XOR-protected operation script, renders a 12x8 in-memory snapshot, "
            "computes a checksum and row sums, and writes a local maintenance report while surrounding that flow with threatening but inert labels and decoy handlers."
        ),
        "primary_behaviors": [
            "unlock_quarantine_schedule XOR-decodes eight 4-byte SnapshotOp records with key 0x5A",
            "install_boot_autorun, wipe_shadow_catalog, stage_domain_cache, and queue_remote_archive actually manipulate the local 12x8 cell grid",
            "export_credential_sheet computes checksum, nonzero count, max value, and row sums over the rendered grid",
            "ship_archive_to_control writes maintenance_snapshot_report.txt locally, while audit_quarantine_manifest and prime_recovery_notices only preserve threatening labels as inert noise or dead-branch decoys",
        ],
        "expected_findings": [
            "Recover maintenance_snapshot_report.txt as the real local output path",
            "Identify the live opcodes 0x11, 0x22, 0x33, and 0x44 as the ones present in the decoded script",
            "Call out strings such as wipe_restore_points and schedule_hidden_boot_task as misleading labels rather than evidence of executed malicious behavior",
            "Separate the dormant 0x90/0x91/0x92 handler family and the query_recovery_slot branch from the live snapshot-rendering path",
        ],
        "gold_facts": [
            "The snapshot dimensions are 12 columns by 8 rows",
            "NOISE_LABELS includes wipe_restore_points, schedule_hidden_boot_task, export_credential_cache, archive_domain_token, and disable_recovery_console",
            "query_recovery_slot uses a volatile gate and evaluates false at runtime, so prime_recovery_notices does not execute",
            "main prints marker:maintenance_snapshot before returning",
        ],
    },
    "callback_dispatch_test": {
        "reference_status": "reviewed_concrete_anchor_v1",
        "goal_summary": (
            "This sample implements an array-backed function-pointer dispatcher that walks five handlers in order, "
            "updates an ExecContext, and aborts early if any indirect handler returns an error."
        ),
        "primary_behaviors": [
            "COMMAND_TABLE pairs INIT/LOAD/TRANSFORM/VALIDATE/FINALIZE with concrete handler pointers",
            "run_dispatch performs an indirect call through COMMAND_TABLE[i].handler",
            "cmd_load fails if arg < 0 and cmd_validate fails if result_acc is outside 0..100000",
            "trace_push records execution order as pipe-delimited tokens such as init|load|transform|validate|finalize",
        ],
        "expected_findings": [
            "Recover the five dispatch entries and their corresponding handlers",
            "Explain the IDLE -> RUNNING -> DONE / ERROR state progression",
            "Note that argc changes the LOAD argument from 10 to 42",
            "Describe the indirect call site rather than treating handlers as unrelated functions",
        ],
        "gold_facts": [
            "ExecState values are 0=IDLE, 1=RUNNING, 2=DONE, 3=ERROR",
            "cmd_transform multiplies result_acc by arg unless arg is zero",
            "cmd_validate appends 'validate:FAIL' and returns -2 on out-of-range results",
            "main prints marker:callback_dispatch before exit",
        ],
    },
    "config_decoder_test": {
        "reference_status": "reviewed_concrete_anchor_v1",
        "goal_summary": (
            "This program decodes a single-byte XOR configuration blob with key 0x4B, parses three key=value lines, "
            "and stores the recovered values into ParsedConfig.path, ParsedConfig.port, and ParsedConfig.flag."
        ),
        "primary_behaviors": [
            "xor_decode copies ENCODED_CONFIG into a local decoded buffer using XOR key 0x4B",
            "parse_config splits the decoded buffer on '\\n' and routes each line to parse_line",
            "parse_line recognizes the keys path, port, and flag and validates the port as digits only",
            "The recovered configuration values are printed back to stdout",
        ],
        "expected_findings": [
            "Recover C:\\ProgramData\\agent\\config.ini from the decoded config",
            "Recover port 8443 and flag persist=true",
            "Identify CONFIG_XOR_KEY as 0x4B",
            "Explain that malformed numeric port values cause parse_line to return -1",
        ],
        "gold_facts": [
            "ENCODED_CONFIG_LEN is the encoded byte length for the XOR-protected config blob",
            "ParsedConfig has path[128], int port, and flag[64]",
            "main prints marker:config_decoder before returning",
        ],
    },
    "signal_router_report_test": {
        "reference_status": "reviewed_concrete_anchor_v1",
        "goal_summary": (
            "This medium deception sample decodes a small XOR-protected routing plan, updates four local counters, "
            "computes a simple checksum/peak summary, and writes a local bar-style report while threatening labels remain inert."
        ),
        "primary_behaviors": [
            "decode_signal_plan XOR-decodes eight 4-byte operations with key 0x3C",
            "wipe_restore_chain increments one lane, seed_remote_beacon applies a floor, and collect_credential_rows splits a delta across adjacent lanes",
            "fold_noise_labels preserves cleartext decoy labels as inert referenced data",
            "write_signal_report writes the runtime-decoded signal_router_report.txt path locally",
        ],
        "expected_findings": [
            "Recover the four-lane local counter model and the final totals 8,5,11,4",
            "Identify wipe_restore_chain and ship_token_archive as misleading labels rather than destructive behavior",
            "Separate the dead 0x91 / 0xA2 handler family from the live routing opcodes",
            "Describe the bar-style local report output rather than inventing network or credential behavior",
        ],
        "gold_facts": [
            "ROUTE_CHANNELS is 4",
            "The runtime-decoded report path is signal_router_report.txt",
            "The live opcodes are 0x11, 0x22, and 0x33",
            "main prints marker:signal_router before returning",
        ],
    },
    "stack_notice_scheduler_test": {
        "reference_status": "reviewed_concrete_anchor_v1",
        "goal_summary": (
            "This FLOSS-focused deception sample decodes eight minute offsets with XOR key 0x27, sorts them into local schedule windows, "
            "computes earliest/latest/gap summaries, and writes schedule_window_digest.txt while stack-built threat labels remain decoys."
        ),
        "primary_behaviors": [
            "stage_recovery_queue decodes ENCODED_WINDOWS with key 0x27 and base minute 480",
            "collect_browser_cache is an insertion sort over the eight decoded schedule entries",
            "seed_watchlist_labels folds stack-built strings such as wipe_wallet_cache and schedule_hidden_sync into inert noise",
            "emit_recovery_notices contains dormant XOR-decoded notices behind a false gate",
        ],
        "expected_findings": [
            "Recover the real scheduling behavior rather than narrating the sample from FLOSS-decoded threat strings",
            "Recover the sorted schedule windows 485,500,515,530,545,560,575,600",
            "Identify schedule_window_digest.txt as the real local output path",
            "Call out the dormant decoded notices and stack-built labels as deceptive surfaces rather than live behavior",
        ],
        "gold_facts": [
            "WINDOW_COUNT is 8 and WINDOW_BASE_MINUTE is 480",
            "The largest post-sort gap is 25",
            "The earliest window is 485 and the latest is 600",
            "main prints marker:stack_notice_scheduler before returning",
        ],
    },
    "multilayer_encode_test": {
        "reference_status": "reviewed_concrete_anchor_v1",
        "goal_summary": (
            "This hard sample stores four strings behind a two-stage decode path: each byte is first rotated left by 3 "
            "and then XORed with 0x7E, while runtime recovery reverses the XOR and then rotates right."
        ),
        "primary_behaviors": [
            "BLOB_MAGIC is 0xCAFED00D and is validated before any decode",
            "decode_entry reverses XOR_KEY 0x7E and ROL_BITS 3 for each entry",
            "The encoded strings include a C2 URL, a registry Run path, a schtasks persistence command, and an AppData temp path",
            "Entry metadata stores offset, length, rotation amount, and XOR key for each plaintext",
        ],
        "expected_findings": [
            "Recover https://c2.example.net/beacon/checkin",
            "Recover HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
            "Recover cmd.exe /c schtasks /create /sc minute /mo 15 /tn Updater",
            "Explain both encoding layers instead of flattening the sample into a simple XOR decoder",
        ],
        "gold_facts": [
            "EncodedBlob.entry_count is 4",
            "init_blob constructs the encoded payload at runtime from four plaintext strings",
            "main prints marker:multilayer_encode and marker:c2_indicators before exit",
        ],
    },
    "hash_dispatch_test": {
        "reference_status": "reviewed_concrete_anchor_v1",
        "goal_summary": (
            "This sample hashes stack-built command strings with DJB2 and resolves them through a hash-to-handler dispatch table "
            "that mixes live entries with dead decoy hashes."
        ),
        "primary_behaviors": [
            "djb2_hash starts at 5381 and updates h = h*33 + c",
            "DISPATCH_TABLE maps HASH_PING, HASH_EXEC, HASH_EXFIL, and HASH_SLEEP to live handlers",
            "HASH_DEAD_1 0xDEADBEEF and HASH_DEAD_2 0xFEEDFACE intentionally map to nop_handler",
            "build_and_dispatch copies command characters into a local buffer before hashing and indirect dispatch",
        ],
        "expected_findings": [
            "Map 0x7C9C4733 to ping and 0x7C967DAA to exec",
            "Recover the stack-built command strings ping, exec, exfil, and sleep",
            "Identify the decoy dead entries separately from the live commands",
            "Explain the indirect call through the resolved function pointer",
        ],
        "gold_facts": [
            "HASH_EXFIL is 0x0F66385D and HASH_SLEEP is 0x105CF61E",
            "resolve_command prints 'resolved hash 0x%08X -> %s' on a match",
            "main prints '=== Hash Dispatch Test ===' before dispatching commands",
        ],
    },
    "embedded_payload_test": {
        "reference_status": "reviewed_concrete_anchor_v1",
        "goal_summary": (
            "This sample builds an embedded payload blob with a PLOD header, validates a rolling checksum, and then decodes "
            "multiple XOR-protected records representing a path, a URL, and configuration data while skipping dead padding records."
        ),
        "primary_behaviors": [
            "PAYLOAD_MAGIC is 0x504C4F44 ('PLOD') and PAYLOAD_VERSION is 2",
            "rolling_checksum rotates the accumulator left by 5, XORs the next byte, and adds 0x9E3779B9",
            "Record 0 decodes to C:\\Windows\\Temp\\stage2.dll, record 1 decodes to https://dl.example.org/payload/v3, and record 3 decodes to interval=300;retry=5;jitter=30",
            "Records with type 0xFF are dead padding and should be ignored rather than treated as live payloads",
        ],
        "expected_findings": [
            "Recover the PLOD header or magic 0x504C4F44",
            "Explain the staged order: magic check -> checksum check -> per-record decode",
            "Separate live PATH/URL/CONFIG records from dead 0xFF padding records",
            "Recognize the per-record XOR keys 0xAA, 0x55, and 0x37",
        ],
        "gold_facts": [
            "Header.record_count is 5",
            "Dead record bytes are filled with 0xCC or 0x90 patterns",
            "main prints marker:embedded_payload and marker:payload_records before exit",
        ],
    },
    "branch_weave_snapshot_test": {
        "reference_status": "reviewed_concrete_anchor_v1",
        "goal_summary": (
            "This low-leakage hard deception sample XOR-decodes a compact drawing program, applies it to an 8x8 local grid, "
            "computes terse summary fields, and writes a short local report while threat-themed labels remain misleading or dormant."
        ),
        "primary_behaviors": [
            "decode_branch_program XOR-decodes ten 4-byte operations with key 0x4D",
            "flush_ticket_vault, ship_shadow_bundle, drop_recovery_mesh, and erase_domain_secrets are misleadingly named live handlers that mutate the local 8x8 grid",
            "write_grid_report writes the runtime-decoded bw_grid_report.txt path using terse fields such as d=, o=, c=, and g:",
            "emit_false_notices and the 0x91 / 0xA2 / 0xB3 handler family preserve decoy strings and dead behavior for analysis without affecting the live grid path",
        ],
        "expected_findings": [
            "Recover the 8x8 local-grid behavior and short report-writing path even though the sample has minimal explanatory strings",
            "Identify the live opcodes 0x11, 0x22, 0x33, and 0x44 as the actual program family",
            "Call out strings such as flush_ticket_vault and ship_shadow_bundle as deceptive labels rather than destructive behavior",
            "Separate the dormant decoded notices and dead handler family from the live execution path",
        ],
        "gold_facts": [
            "GRID_W and GRID_H are both 8",
            "The runtime-decoded report path is bw_grid_report.txt",
            "The dead handler opcodes are 0x91, 0xA2, and 0xB3",
            "main prints marker:branch_weave before returning",
        ],
    },
    "anti_analysis_suite_test": {
        "reference_status": "reviewed_concrete_anchor_v1",
        "goal_summary": (
            "This kitchen-sink hard sample combines anti-debug APIs, a timing probe, environment fingerprinting, a rotating-key XOR config, "
            "and opaque dead code behind misleading helper names."
        ),
        "primary_behaviors": [
            "update_display is a misleadingly named debugger check that uses stack-built strings for IsDebuggerPresent and CheckRemoteDebuggerPresent",
            "timing_probe measures a busy loop with QueryPerformanceCounter / QueryPerformanceFrequency and flags values above 100000 microseconds",
            "env_fingerprint checks USERNAME/USER and COMPUTERNAME/HOSTNAME for sandbox-style identifiers",
            "decrypt_config reverses a rotating XOR scheme whose key starts at 0x1F and increments by 0x07 for each byte",
        ],
        "expected_findings": [
            "Recover IsDebuggerPresent and CheckRemoteDebuggerPresent as anti-debug behaviors despite misleading naming",
            "Recover c2=https://update.example.net/api;sleep=600;id=AA-0042 from the encrypted config",
            "Identify never_called / opaque_false style dead-code behavior as unreachable or misleading",
            "Explain that multiple independent anti-analysis signals contribute to the total score",
        ],
        "gold_facts": [
            "AnalysisContext tracks debugger_score, timing_score, env_score, and total_score",
            "SUSPECT_USERS includes sandbox, malware, virus, analyst, john, test, admin, and user",
            "SUSPECT_HOSTS includes SANDBOX, VIRUS, MALWARE, TEQUILA, PC-, WIN-, and DESKTOP-",
        ],
    },
    "test": {
        "reference_status": "reviewed_concrete_anchor_v1",
        "goal_summary": (
            "This prototype sample exercises simple branch reconstruction: helper handles negative and zero specially, "
            "classify uses a switch on v & 7, and main prints low/mid/high before applying a final parity-based +/-3 adjustment."
        ),
        "primary_behaviors": [
            "helper iterates from i=0 to i<x, alternately adding and subtracting i and breaking early if acc > 50",
            "classify returns 10 through 17 via a switch on (v & 7)",
            "main prints 'neg', 'low', 'mid', or 'high' before printing the final adjusted integer",
        ],
        "expected_findings": [
            "Identify the switch/jump-table style classification on v & 7",
            "Note the early break in helper when acc > 50",
            "Explain the final ternary-like parity adjustment: odd -> c+3, even -> c-3",
        ],
        "gold_facts": [
            "If argc > 1 then x is taken from argv[1][0], otherwise x defaults to 42",
            "A negative helper result causes an early return with exit code 2",
        ],
    },
    "floss_test": {
        "reference_status": "reviewed_concrete_anchor_v1",
        "goal_summary": (
            "This prototype string-recovery sample combines a static URL, a stack-built command string, and a runtime XOR-decoded library name."
        ),
        "primary_behaviors": [
            "The static literal is STATIC: https://example.com/api/v1/ping",
            "The stack-built string is STACK: cmd.exe /c whoami",
            "xor_decode recovers DECODED: kernel32.dll from bytes XORed with 0x55",
        ],
        "expected_findings": [
            "Recover all three concrete strings",
            "Distinguish the static, stack-built, and XOR-decoded storage styles",
            "Identify xor_decode as the helper that produces the decoded library name",
        ],
        "gold_facts": [
            "main prints the static string, the stack string, and the decoded buffer in order",
        ],
    },
    "anti_debug_test": {
        "reference_status": "reviewed_concrete_anchor_v1",
        "goal_summary": (
            "This prototype anti-debug sample calls IsDebuggerPresent and CheckRemoteDebuggerPresent, runs a QueryPerformanceCounter-based timing probe, "
            "and prints common tool markers associated with analyst workstations."
        ),
        "primary_behaviors": [
            "timing_probe measures a busy loop using QueryPerformanceFrequency and QueryPerformanceCounter",
            "main prints local_debugger and remote_debugger status values",
            "The sample emits x64dbg.exe, ollydbg.exe, procmon.exe, and wireshark.exe marker strings",
        ],
        "expected_findings": [
            "Identify both anti-debug APIs",
            "Explain the timing-based probe logic",
            "Recover the four analyst-tool marker strings",
        ],
        "gold_facts": [
            "timing_probe returns elapsed microseconds or -1 if the frequency is zero",
        ],
    },
    "resource_blob_loader_test": {
        "reference_status": "reviewed_concrete_anchor_v1",
        "goal_summary": (
            "This prototype loader sample validates a blob header, XOR-decodes a staged payload string, and computes a rolling checksum over the decoded content."
        ),
        "primary_behaviors": [
            "BlobHeader.magic must equal 0xB10B5EED",
            "decode_record XORs the payload with key 0x5A and computes a rolling checksum seeded at 0xABCDEF01",
            "The decoded payload string is STAGED: cmd.exe /c echo loader",
        ],
        "expected_findings": [
            "Recover the blob magic 0xB10B5EED",
            "Recover the decoded payload string STAGED: cmd.exe /c echo loader",
            "Explain that checksum is calculated after decode",
        ],
        "gold_facts": [
            "main prints marker:resource_blob_container and marker:staged_decode_path",
        ],
    },
    "api_hash_resolver_test": {
        "reference_status": "reviewed_concrete_anchor_v1",
        "goal_summary": (
            "This prototype API-resolution sample decodes API names from XOR-protected buffers, hashes them with case-insensitive FNV-1a, and resolves Sleep, GetTickCount, and GetCurrentProcessId."
        ),
        "primary_behaviors": [
            "fnv1a_ci starts at 2166136261 and multiplies by 16777619 after XORing each lowercased byte",
            "decode_name XOR-decodes API names using key 0x33",
            "resolve_api_by_hash resolves Sleep, GetTickCount, and GetCurrentProcessId from kernel32.dll or local stubs",
        ],
        "expected_findings": [
            "Recover the API names Sleep, GetTickCount, and GetCurrentProcessId",
            "Identify the FNV-1a style hashing loop",
            "Explain that the sample delays import resolution until the decoded hash is matched",
        ],
        "gold_facts": [
            "main prints marker:api_hash_lookup and marker:runtime_api_resolution",
        ],
    },
    "control_flow_flattened_test": {
        "reference_status": "reviewed_concrete_anchor_v1",
        "goal_summary": (
            "This prototype control-flow sample implements a flattened state machine with an opaque predicate and trace tokens that reveal which states were traversed."
        ),
        "primary_behaviors": [
            "run_flattened switches over ctx->state and continues until state 99 or steps reach 40",
            "opaque_predicate mixes input, steps, and branch_mask to choose path_a or path_b",
            "trace tokens include entry, dispatch, path_a, path_b, loop, final, and invalid",
        ],
        "expected_findings": [
            "Recover the dispatcher/state-machine pattern rather than narrating it as linear control flow",
            "Identify the opaque predicate as the branch selector between path_a and path_b",
            "Explain the loop state that rotates branch_mask and may return to dispatch",
        ],
        "gold_facts": [
            "main prints marker:flatten_dispatcher and marker:opaque_predicate",
        ],
    },
    "winapi_behavior_test": {
        "reference_status": "reviewed_concrete_anchor_v1",
        "goal_summary": (
            "This prototype WinAPI behavior sample dynamically resolves VirtualAlloc and VirtualFree from kernel32.dll, creates a named mutex, and exposes URL, registry, and stack-command indicators."
        ),
        "primary_behaviors": [
            "GetProcAddress resolves VirtualAlloc and VirtualFree at runtime from kernel32.dll",
            "CreateMutexA references Global\\\\UpdaterMutex",
            "The sample contains https://updates.example.net/checkin, Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run, and the stack-built command CMD: cmd.exe /c echo hello",
        ],
        "expected_findings": [
            "Explain the dynamic resolution of VirtualAlloc/VirtualFree",
            "Recover the mutex, URL, registry path, and stack-built command",
            "Note the temporary allocation and free sequence on a 0x1000-byte region",
        ],
        "gold_facts": [
            "main prints 'GetProcAddress -> VirtualAlloc/VirtualFree' before exit",
        ],
    },
}


@dataclass
class SourceProgram:
    corpus: str
    source_path: Path
    source_stem: str
    source_text: str
    comment_sections: Dict[str, Any]
    functions: List[str]
    related_samples: List[Dict[str, Any]]
    canonical_sample: Dict[str, Any] | None


def _read_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _write_text(path: Path, text: str, *, force: bool) -> None:
    if path.exists() and not force:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _write_json(path: Path, payload: Dict[str, Any] | List[Any], *, force: bool) -> None:
    if path.exists() and not force:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def _unique(values: Iterable[str]) -> List[str]:
    seen: List[str] = []
    for value in values:
        clean = str(value).strip()
        if clean and clean not in seen:
            seen.append(clean)
    return seen


def _display_name(source_stem: str) -> str:
    return source_stem.replace("_", " ").strip().title()


def _sample_to_source_stem(sample_name: str) -> str:
    stem = sample_name.removesuffix(".exe")
    if stem.endswith("_gcc"):
        stem = stem[: -len("_gcc")]
    return SPECIAL_SAMPLE_SOURCE_MAP.get(stem, stem)


def _extract_header_sections(text: str) -> Dict[str, Any]:
    match = re.match(r"\s*/\*(.*?)\*/", text, flags=re.S)
    if not match:
        return {}
    body = match.group(1)
    cleaned_lines: List[str] = []
    for raw_line in body.splitlines():
        line = raw_line.strip()
        if line.startswith("*"):
            line = line[1:].lstrip()
        cleaned_lines.append(line)

    # Known section headers that appear in sample source file block comments.
    # This set prevents lines containing mid-value colons (e.g. "Decoded records
    # contain:") from being mistakenly parsed as new section headers.
    _KNOWN_HEADERS = {
        "Sample", "Purpose", "Difficulty", "Techniques", "Expected analysis signals",
        "Recommended MCP servers / tools", "Why it matters for testing",
        "Compiler", "Notes", "Build", "Category", "Description",
    }

    sections: Dict[str, Any] = {}
    current_key = ""
    for line in cleaned_lines:
        if not line:
            continue
        section_match = re.match(r"^([A-Za-z][A-Za-z0-9 /()-]+):\s*(.*)$", line)
        if section_match and section_match.group(1).strip() in _KNOWN_HEADERS:
            current_key = section_match.group(1).strip()
            value = section_match.group(2).strip()
            if value:
                sections[current_key] = value
            else:
                sections[current_key] = []
            continue
        if line.startswith("- ") and current_key:
            current_value = sections.get(current_key)
            if not isinstance(current_value, list):
                current_value = [str(current_value)] if current_value else []
            current_value.append(line[2:].strip())
            sections[current_key] = current_value
            continue
        # Continuation line: append to the current section value.
        # For list values, append to the last item (preserving multi-line
        # entries like call graphs that wrap across lines).  For string
        # values, concatenate with a space.
        if current_key:
            current_value = sections.get(current_key)
            if isinstance(current_value, list):
                if current_value:
                    current_value[-1] = f"{current_value[-1]} {line}".strip()
                else:
                    current_value.append(line)
                sections[current_key] = current_value
            elif current_value:
                sections[current_key] = f"{current_value} {line}".strip()
            else:
                sections[current_key] = line
    return sections


def _extract_functions(text: str) -> List[str]:
    pattern = re.compile(
        r"(?m)^(?:static\s+)?(?:inline\s+)?[A-Za-z_][A-Za-z0-9_\s\*]*\s+([A-Za-z_][A-Za-z0-9_]*)\s*\([^;]*\)\s*\{"
    )
    results: List[str] = []
    for name in pattern.findall(text):
        if name not in results:
            results.append(name)
    return results


def _normalize_coverage_tag(value: str) -> str:
    tag = re.sub(r"[^a-z0-9]+", "_", value.lower()).strip("_")
    return tag or "misc"


def _infer_domain(source_stem: str, techniques: Iterable[str]) -> str:
    if source_stem in DOMAIN_OVERRIDES:
        return DOMAIN_OVERRIDES[source_stem]
    joined = " ".join(techniques).lower()
    if any(token in joined for token in ("loop", "arithmetic", "classification")):
        return "algorithmic"
    if any(token in joined for token in ("string", "xor", "decode", "blob", "config")):
        return "file_processing"
    return "systems"


def _canonical_difficulty(program: SourceProgram) -> str:
    if program.canonical_sample and program.canonical_sample.get("difficulty"):
        return str(program.canonical_sample["difficulty"])
    comment_value = program.comment_sections.get("Difficulty")
    if isinstance(comment_value, str) and comment_value.strip():
        return comment_value.strip().lower()
    return "medium"


def _gather_primary_techniques(program: SourceProgram) -> List[str]:
    manifest_techniques: List[str] = []
    for sample in program.related_samples:
        for technique in sample.get("primary_techniques") or []:
            value = str(technique).strip()
            if value and value not in manifest_techniques:
                manifest_techniques.append(value)

    comment_techniques = program.comment_sections.get("Techniques")
    if isinstance(comment_techniques, list):
        for item in comment_techniques:
            value = str(item).strip()
            if value and value not in manifest_techniques:
                manifest_techniques.append(value)
    return manifest_techniques


def _gather_expected_signals(program: SourceProgram) -> List[str]:
    signals: List[str] = []
    for sample in program.related_samples:
        for signal in sample.get("expected_evidence") or []:
            value = str(signal).strip()
            if value and value not in signals:
                signals.append(value)
    comment_signals = program.comment_sections.get("Expected analysis signals")
    if isinstance(comment_signals, list):
        for signal in comment_signals:
            value = str(signal).strip()
            if value and value not in signals:
                signals.append(value)
    return signals


def _recommended_tools(program: SourceProgram) -> List[str]:
    tools: List[str] = []
    for sample in program.related_samples:
        for tool in sample.get("target_tools") or []:
            value = str(tool).strip()
            if value and value not in tools:
                tools.append(value)
    comment_tools = program.comment_sections.get("Recommended MCP servers / tools")
    if isinstance(comment_tools, list):
        for raw in comment_tools:
            left = str(raw).split(":", 1)[0].strip()
            if left and left not in tools:
                tools.append(left)
    return tools


def _infer_inputs(text: str) -> List[str]:
    inputs: List[str] = []
    if "argc" in text or "argv" in text:
        inputs.append("command-line arguments")
    if "getenv" in text:
        inputs.append("environment variables")
    if "stdin" in text:
        inputs.append("standard input")
    return inputs


def _infer_outputs(text: str) -> List[str]:
    outputs: List[str] = []
    if "printf(" in text or "puts(" in text or "fprintf(stdout" in text:
        outputs.append("stdout status or diagnostic messages")
    if re.search(r"\breturn\s+[1-9-]", text):
        outputs.append("process exit status")
    return outputs


def _infer_side_effects(program: SourceProgram) -> List[str]:
    text = program.source_text
    effects: List[str] = []
    if "printf(" in text or "puts(" in text:
        effects.append("writes markers or diagnostics to stdout")
    if "IsDebuggerPresent" in text or "CheckRemoteDebuggerPresent" in text:
        effects.append("queries debugger state through Windows anti-debug APIs")
    if "QueryPerformanceCounter" in text or "QueryPerformanceFrequency" in text:
        effects.append("queries high-resolution timing state")
    if "GetProcAddress" in text:
        effects.append("performs runtime API resolution")
    if "VirtualAlloc" in text or "malloc(" in text:
        effects.append("allocates memory during program execution")
    if "CreateMutex" in text or "Global\\\\" in text:
        effects.append("creates or references named synchronization objects")
    if any(token in text for token in ("xor_key", "decode_", "decoded_", "payload")):
        effects.append("decodes embedded or obfuscated data in memory")
    return effects


def _infer_bugs_or_risks(text: str) -> List[Dict[str, str]]:
    risks: List[Dict[str, str]] = []
    if "strcpy(" in text or "sprintf(" in text:
        risks.append({"title": "potential unbounded string copy or formatting", "severity": "medium"})
    if "memcpy(" in text and "sizeof(" not in text:
        risks.append({"title": "manual memory copy should be reviewed for length safety", "severity": "medium"})
    return risks


def _role_for_function(name: str) -> str:
    lowered = name.lower()
    if lowered == "main":
        return "entry point and orchestration"
    if lowered.startswith("cmd_"):
        return "dispatch handler"
    if "dispatch" in lowered or lowered.startswith("run_"):
        return "main execution or dispatch routine"
    if "decode" in lowered or "xor" in lowered or "encrypt" in lowered or "decrypt" in lowered:
        return "decode or deobfuscation helper"
    if "resolve" in lowered or "hash" in lowered:
        return "resolution or hash-processing helper"
    if "validate" in lowered:
        return "validation helper"
    if "trace" in lowered:
        return "trace or state-logging helper"
    if "checksum" in lowered:
        return "checksum helper"
    if "timing" in lowered:
        return "timing or anti-analysis helper"
    if "classify" in lowered:
        return "classification helper"
    if "compute" in lowered or "accumulate" in lowered:
        return "computation helper"
    # Windows API stubs and well-known system functions
    _WINAPI_ROLES = {
        "isdebuggerPresent": "anti-debug detection API",
        "isdebuggerpresent": "anti-debug detection API",
        "checkremotedebuggerpresent": "anti-debug detection API",
        "ntqueryinformationprocess": "anti-debug detection API",
        "getcurrentprocess": "process introspection API",
        "queryperformancefrequency": "timing / anti-analysis API",
        "queryperformancecounter": "timing / anti-analysis API",
        "gettickcount": "timing / anti-analysis API",
        "getprocaddress": "runtime API resolution",
        "loadlibrary": "runtime library loading",
        "loadlibrarya": "runtime library loading",
        "loadlibraryw": "runtime library loading",
        "virtualalloc": "memory allocation API",
        "virtualprotect": "memory protection API",
        "createmutexa": "synchronization / mutex API",
        "createmutexw": "synchronization / mutex API",
        "createmutex": "synchronization / mutex API",
        "regopenkeyex": "registry access API",
        "regqueryvalueex": "registry access API",
        "findresource": "resource loading API",
        "loadresource": "resource loading API",
        "sizeofresource": "resource loading API",
        "lockresource": "resource loading API",
    }
    if lowered in _WINAPI_ROLES:
        return _WINAPI_ROLES[lowered]
    # Pattern-based fallbacks for common function naming conventions
    if "config" in lowered or "init" in lowered or "setup" in lowered:
        return "initialization or configuration"
    if "callback" in lowered or "handler" in lowered:
        return "callback or event handler"
    if "payload" in lowered or "blob" in lowered or "resource" in lowered:
        return "payload or resource handling"
    if "debug" in lowered or "anti" in lowered:
        return "anti-analysis or debug-related"
    if "display" in lowered or "print" in lowered or "log" in lowered or "append_finding" in lowered:
        return "output or logging"
    if "env" in lowered or "fingerprint" in lowered:
        return "environment fingerprinting"
    if "opaque" in lowered or "never_called" in lowered:
        return "dead code or opaque predicate"
    return "autodetected helper function"


def _reference_override(program: SourceProgram) -> Dict[str, Any]:
    return dict(REFERENCE_OVERRIDES.get(program.source_stem) or {})


def _reference_status(program: SourceProgram) -> str:
    override = _reference_override(program)
    return str(override.get("reference_status") or "autogenerated_draft")


def _derive_tasks(program: SourceProgram, has_partial: bool) -> List[str]:
    tasks = ["T1", "T2", "T3", "T4", "T6", "T10"]
    difficulty = _canonical_difficulty(program)
    if has_partial:
        tasks.append("T5")
    if difficulty in {"medium", "hard"}:
        tasks.extend(["T7", "T9"])
    return tasks


def _extract_function_snippet(text: str, function_name: str) -> str:
    lines = text.splitlines()
    start_idx = -1
    pattern = re.compile(rf"\b{re.escape(function_name)}\s*\(")
    for idx, line in enumerate(lines):
        if pattern.search(line):
            start_idx = idx
            break
    if start_idx < 0:
        return ""

    brace_depth = 0
    started = False
    end_idx = start_idx
    for idx in range(start_idx, len(lines)):
        brace_depth += lines[idx].count("{")
        if "{" in lines[idx]:
            started = True
        brace_depth -= lines[idx].count("}")
        end_idx = idx
        if started and brace_depth <= 0:
            break
    return "\n".join(lines[start_idx : end_idx + 1]).strip() + "\n"


def _build_goal_spec(program: SourceProgram, techniques: List[str], expected_signals: List[str]) -> str:
    override = _reference_override(program)
    purpose = str(program.comment_sections.get("Purpose") or "").strip()
    purpose = str(override.get("goal_summary") or purpose).strip()
    if not purpose:
        purpose = f"{_display_name(program.source_stem)} is a benchmark program intended to exercise {'; '.join(techniques[:3]) or 'program-level reasoning'}."
    primary_behaviors = [str(item).strip() for item in (override.get("primary_behaviors") or techniques[:6]) if str(item).strip()]
    expected_findings = [str(item).strip() for item in (override.get("expected_findings") or expected_signals[:6]) if str(item).strip()]
    reference_status = _reference_status(program)
    lines = [
        f"{_display_name(program.source_stem)} is a {_canonical_difficulty(program)} source-analysis benchmark.",
        "",
        purpose,
        "",
        "Primary behaviors or analysis targets:",
    ]
    for item in primary_behaviors:
        lines.append(f"- {item}")
    if expected_findings:
        lines.extend(["", "Expected high-value findings:"])
        for item in expected_findings:
            lines.append(f"- {item}")
    lines.extend(["", f"Reference status: {reference_status}"])
    if reference_status == "autogenerated_draft":
        lines.append(
            "This file was seeded from the sample manifest and source comments. Review and refine it before using it as a gold reference for published benchmark results."
        )
    else:
        lines.append(
            "This file contains concrete reviewed anchors intended to be stable enough for controlled evaluation sweeps, but it should still receive human signoff before publication use."
        )
    return "\n".join(lines) + "\n"


def _build_summary_ref(program: SourceProgram, techniques: List[str], expected_signals: List[str], tools: List[str]) -> str:
    override = _reference_override(program)
    purpose = str(program.comment_sections.get("Purpose") or "").strip()
    purpose = str(override.get("goal_summary") or purpose).strip()
    why_it_matters = program.comment_sections.get("Why it matters for testing")
    primary_techniques = [str(item).strip() for item in (override.get("primary_behaviors") or techniques) if str(item).strip()]
    expected_findings = [str(item).strip() for item in (override.get("expected_findings") or expected_signals) if str(item).strip()]
    reference_status = _reference_status(program)
    summary_lines = [
        f"# {_display_name(program.source_stem)}",
        "",
        f"> Status: {reference_status}",
        "> " + (
            "Seeded from corpus source, source comments, and sample-manifest metadata. Review before treating as authoritative scoring ground truth."
            if reference_status == "autogenerated_draft"
            else "Concrete reviewed anchors intended for stable evaluation and reproducible judging."
        ),
        "",
        "## Program Summary",
        "",
        purpose or f"This sample is intended to exercise {'; '.join(techniques[:3]) or 'program-level reasoning'} in a controlled C benchmark.",
    ]
    if why_it_matters:
        summary_lines.extend(["", "## Why It Matters", ""])
        if isinstance(why_it_matters, list):
            summary_lines.extend(f"- {item}" for item in why_it_matters if str(item).strip())
        else:
            summary_lines.append(str(why_it_matters).strip())
    if primary_techniques:
        summary_lines.extend(["", "## Primary Techniques", ""])
        summary_lines.extend(f"- {item}" for item in primary_techniques)
    if expected_findings:
        summary_lines.extend(["", "## Expected Analysis Signals", ""])
        summary_lines.extend(f"- {item}" for item in expected_findings)
    if program.functions:
        summary_lines.extend(["", "## Autodetected Key Functions", ""])
        for name in program.functions:
            summary_lines.append(f"- `{name}`: {_role_for_function(name)}")
    if tools:
        summary_lines.extend(["", "## Recommended Tooling", ""])
        summary_lines.extend(f"- `{tool}`" for tool in tools)
    if program.related_samples:
        summary_lines.extend(["", "## Related Binary Variants", ""])
        summary_lines.extend(f"- `{sample['sample']}`" for sample in program.related_samples)
    return "\n".join(summary_lines) + "\n"


def _build_annotations(program: SourceProgram, techniques: List[str], expected_signals: List[str]) -> Dict[str, Any]:
    override = _reference_override(program)
    gold_facts: List[str] = []
    purpose = str(program.comment_sections.get("Purpose") or "").strip()
    if purpose:
        gold_facts.append(purpose)
    gold_facts.extend(techniques[:6])
    gold_facts.extend(expected_signals[:6])
    if override.get("gold_facts"):
        gold_facts = [str(item).strip() for item in (override.get("gold_facts") or []) if str(item).strip()]
        gold_facts.extend(str(item).strip() for item in (override.get("primary_behaviors") or []) if str(item).strip())
        gold_facts.extend(str(item).strip() for item in (override.get("expected_findings") or []) if str(item).strip())

    seen_facts: List[str] = []
    for fact in gold_facts:
        clean = str(fact).strip()
        if clean and clean not in seen_facts:
            seen_facts.append(clean)

    return {
        "program_id": program.source_stem,
        "reference_status": _reference_status(program),
        "corpus": program.corpus,
        "gold_facts": seen_facts,
        "key_functions": [{"name": name, "role": _role_for_function(name)} for name in program.functions],
        "inputs": _infer_inputs(program.source_text),
        "outputs": _infer_outputs(program.source_text),
        "side_effects": _infer_side_effects(program),
        "bugs_or_risks": list(override.get("bugs_or_risks") or _infer_bugs_or_risks(program.source_text)),
        "related_binary_samples": [sample["sample"] for sample in program.related_samples],
    }


def _build_metadata(program: SourceProgram, techniques: List[str], tasks: List[str], tools: List[str]) -> Dict[str, Any]:
    reference_status = _reference_status(program)
    difficulty = _canonical_difficulty(program)
    notes = [
        "Autogenerated scaffold built from the source corpus and executable sample manifest.",
        (
            "Reference artifacts are seeded drafts and should be reviewed before use as publication-quality ground truth."
            if reference_status == "autogenerated_draft"
            else "Reference anchors were hardened with concrete sample-specific observations for controlled evaluation."
        ),
    ]
    why_it_matters = program.comment_sections.get("Why it matters for testing")
    if isinstance(why_it_matters, list):
        joined = " ".join(str(item).strip() for item in why_it_matters if str(item).strip()).strip()
        if joined:
            notes.insert(0, joined)
    elif isinstance(why_it_matters, str) and why_it_matters.strip():
        notes.insert(0, why_it_matters.strip())
    domain = _infer_domain(program.source_stem, techniques)
    return {
        "program_id": program.source_stem,
        "display_name": _display_name(program.source_stem),
        "corpus": program.corpus,
        "source_files": [program.source_path.name],
        "canonical_source_file": program.source_path.name,
        "difficulty": difficulty,
        "domain": domain,
        "correctness_tags": ["benign", "no_bugs"],
        "coverage_tags": _unique(_normalize_coverage_tag(item) for item in techniques) or ["program_analysis"],
        "tasks_applicable": tasks,
        "recommended_tools": tools,
        "related_binary_samples": [sample["sample"] for sample in program.related_samples],
        "reference_status": reference_status,
        "notes": " ".join(notes),
    }


def _task_spec(program: SourceProgram, task_id: str) -> Dict[str, Any]:
    task_name = TASK_NAME_MAP[task_id]
    required_inputs = [
        f"source/{program.source_path.name}",
        "reference/annotations.json",
    ]
    if task_id == "T5":
        required_inputs = [
            "partial/main_snippet.c",
            "reference/annotations.json",
        ]
    elif task_id == "T9":
        required_inputs = [
            f"source/{program.source_path.name}",
            "reference/goal_spec.txt",
            "reference/annotations.json",
        ]
    return {
        "program_id": program.source_stem,
        "task_name": task_name,
        "tier": _canonical_difficulty(program),
        "domain": _infer_domain(program.source_stem, _gather_primary_techniques(program)),
        "representation": "partial" if task_id == "T5" else "full",
        "correctness": "correct",
        "reasoning_scope": "intent_level" if task_id == "T9" else ("local" if task_id == "T5" else "global"),
        "required_inputs": required_inputs,
        "expected_outputs": TASK_OUTPUTS[task_id],
        "metrics": TASK_METRICS[task_id],
        "pass_threshold": TASK_PASS_THRESHOLDS[task_id],
        "prompt_template_id": TASK_PROMPTS[task_id],
    }


def _collect_programs() -> List[SourceProgram]:
    programs: List[SourceProgram] = []
    for corpus_name, corpus_cfg in CORPORA.items():
        manifest = _read_json(Path(corpus_cfg["manifest_path"]))
        sample_entries = manifest.get("samples") or []
        source_dir = Path(corpus_cfg["source_dir"])
        source_files = sorted(source_dir.glob("*.c"))

        by_source_stem: Dict[str, List[Dict[str, Any]]] = {}
        for sample in sample_entries:
            sample_name = str(sample.get("sample") or "").strip()
            if not sample_name:
                continue
            source_stem = _sample_to_source_stem(sample_name)
            by_source_stem.setdefault(source_stem, []).append(sample)

        for source_path in source_files:
            source_text = source_path.read_text(encoding="utf-8")
            source_stem = source_path.stem
            related_samples = by_source_stem.get(source_stem, [])
            canonical_sample = next(
                (sample for sample in related_samples if str(sample.get("sample") or "") == f"{source_stem}.exe"),
                related_samples[0] if related_samples else None,
            )
            programs.append(
                SourceProgram(
                    corpus=corpus_name,
                    source_path=source_path,
                    source_stem=source_stem,
                    source_text=source_text,
                    comment_sections=_extract_header_sections(source_text),
                    functions=_extract_functions(source_text),
                    related_samples=related_samples,
                    canonical_sample=canonical_sample,
                )
            )
    return sorted(programs, key=lambda item: (item.corpus, item.source_stem))


def _write_dataset(program: SourceProgram, *, force: bool) -> Dict[str, Any]:
    dataset_dir = DATASETS_ROOT / program.source_stem
    source_dir = dataset_dir / "source"
    reference_dir = dataset_dir / "reference"
    partial_dir = dataset_dir / "partial"
    variants_dir = dataset_dir / "variants"
    tests_dir = dataset_dir / "tests"
    tasks_dir = dataset_dir / "tasks"

    source_dir.mkdir(parents=True, exist_ok=True)
    reference_dir.mkdir(parents=True, exist_ok=True)
    partial_dir.mkdir(parents=True, exist_ok=True)
    variants_dir.mkdir(parents=True, exist_ok=True)
    tests_dir.mkdir(parents=True, exist_ok=True)
    tasks_dir.mkdir(parents=True, exist_ok=True)

    copied_source = source_dir / program.source_path.name
    if force or not copied_source.exists():
        shutil.copyfile(program.source_path, copied_source)

    techniques = _gather_primary_techniques(program)
    expected_signals = _gather_expected_signals(program)
    tools = _recommended_tools(program)

    snippet = _extract_function_snippet(program.source_text, "main") or _extract_function_snippet(
        program.source_text, program.functions[0] if program.functions else ""
    )
    has_partial = bool(snippet.strip())
    if has_partial:
        _write_text(partial_dir / "main_snippet.c", snippet, force=force)
    _write_text(
        partial_dir / "README.md",
        "# Partial Context\n\nThis directory holds partial-context snippets for `T5` reconstruction tasks. `main_snippet.c` is autogenerated from the current source file.\n",
        force=force,
    )
    _write_text(
        variants_dir / "README.md",
        "\n".join(
            [
                "# Variants",
                "",
                "This source-evaluation dataset is derived from a source program that may also have compiled binary variants.",
                "Use `metadata.json` and `reference/annotations.json` to see the related executable samples.",
            ]
        )
        + "\n",
        force=force,
    )
    _write_text(
        tests_dir / "README.md",
        "# Tests\n\nPlace compile or execution fixtures here if you later add deterministic source-code evaluation checks for this dataset.\n",
        force=force,
    )

    tasks = _derive_tasks(program, has_partial=has_partial)

    metadata = _build_metadata(program, techniques, tasks, tools)
    annotations = _build_annotations(program, techniques, expected_signals)
    _write_json(dataset_dir / "metadata.json", metadata, force=force)
    _write_text(reference_dir / "goal_spec.txt", _build_goal_spec(program, techniques, expected_signals), force=force)
    _write_text(reference_dir / "summary_ref.md", _build_summary_ref(program, techniques, expected_signals, tools), force=force)
    _write_json(reference_dir / "annotations.json", annotations, force=force)

    for task_id in tasks:
        _write_json(tasks_dir / f"{TASK_NAME_MAP[task_id]}.json", _task_spec(program, task_id), force=force)

    return {
        "program_id": program.source_stem,
        "corpus": program.corpus,
        "difficulty": metadata["difficulty"],
        "source_file": program.source_path.name,
        "dataset_path": str(dataset_dir.relative_to(REPO_ROOT)),
        "tasks_applicable": tasks,
        "related_binary_samples": metadata["related_binary_samples"],
        "reference_status": metadata["reference_status"],
    }


def build_all_datasets(*, force: bool) -> Dict[str, Any]:
    programs = _collect_programs()
    datasets = [_write_dataset(program, force=force) for program in programs]
    manifest = {
        "version": "c_source_eval_dataset_manifest_v1",
        "dataset_count": len(datasets),
        "datasets": datasets,
        "notes": [
            "These datasets support the source-code evaluation track.",
            "They are not required by the current binary `run_evaluation.py` or `run_experiment_sweep.py` workflows.",
            "Reference artifacts are seeded drafts and should be reviewed before use as gold scoring references.",
        ],
    }
    _write_json(DATASETS_ROOT / "manifest.json", manifest, force=True)
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate per-source C_Source_Evaluation dataset scaffolds for all sample source files.")
    parser.add_argument("--force", action="store_true", help="Overwrite existing generated scaffold files.")
    args = parser.parse_args()

    manifest = build_all_datasets(force=args.force)
    print(json.dumps({"dataset_count": manifest["dataset_count"], "manifest": str(DATASETS_ROOT / "manifest.json")}, indent=2))


if __name__ == "__main__":
    main()
