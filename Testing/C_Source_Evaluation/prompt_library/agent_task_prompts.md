# Agent Task Prompt Library

Use these prompts as versioned templates. Keep placeholders explicit and avoid ad hoc wording changes during evaluation.

Prompt version: `c_source_eval_v1`

---

## General Prompting Rules

- Use the same output format for the same task across all benchmark items.
- Do not mix task prompts with judge prompts.
- Store the exact prompt text used in the run manifest.
- Prefer scoped prompts over one broad prompt that asks for everything.

Common placeholders:

- `{{PROGRAM_ID}}`
- `{{SOURCE_CODE}}`
- `{{SOURCE_TREE_DESCRIPTION}}`
- `{{PARTIAL_CONTEXT}}`
- `{{REFERENCE_SPEC}}`
- `{{VERSION_A_CODE}}`
- `{{VERSION_B_CODE}}`

---

## T1 Program Behavior Summary

```text
You are analyzing C source code for benchmark item {{PROGRAM_ID}}.

Task: summarize the program's behavior.

Requirements:
- Explain what the program does at a behavioral level.
- Identify the main execution path.
- Mention the most important inputs, outputs, and side effects.
- Do not speculate beyond what the source supports.
- If uncertain, label the uncertainty explicitly.

Output format:
1. Short summary (2-4 sentences)
2. Main behaviors
3. Inputs / outputs
4. Side effects
5. Uncertainties

Source:
{{SOURCE_CODE}}
```

---

## T2 Goal / Specification Inference

```text
You are analyzing C source code for benchmark item {{PROGRAM_ID}}.

Task: infer the intended goal or specification of the program.

Requirements:
- State the likely goal in plain language.
- Describe what the program appears designed to guarantee or compute.
- Separate confirmed intent from inference.
- Do not simply restate code structure.

Output format:
1. Inferred goal
2. Evidence from source
3. Likely assumptions or preconditions
4. Uncertainties

Source:
{{SOURCE_CODE}}
```

---

## T3 Function / I/O / Side-Effect Map

```text
You are analyzing C source code for benchmark item {{PROGRAM_ID}}.

Task: identify the key functions, inputs, outputs, external interactions, and side effects.

Requirements:
- List only the functions that materially affect program behavior.
- Identify explicit inputs and outputs.
- Identify file, network, global-state, memory-allocation, or environment side effects if present.
- Keep the map concise and structured.

Output format:
1. Key functions
2. Inputs
3. Outputs
4. Side effects
5. Important data dependencies

Source:
{{SOURCE_CODE}}
```

---

## T4 Control-Flow and Data-Flow Explanation

```text
You are analyzing C source code for benchmark item {{PROGRAM_ID}}.

Task: explain the main control flow and important data flow.

Requirements:
- Describe the major branches, loops, dispatch, and early exits.
- Explain how important values are transformed and propagated.
- Focus on logic that changes observable behavior.

Output format:
1. Entry path
2. Major branches and loops
3. Important data transformations
4. Exit conditions / terminal behaviors

Source:
{{SOURCE_CODE}}
```

---

## T5 Partial-Context Logic Reconstruction

```text
You are analyzing incomplete C source for benchmark item {{PROGRAM_ID}}.

Task: reconstruct likely behavior from partial context.

Requirements:
- Infer what the code likely does using only the provided snippet and context.
- Distinguish direct evidence from inference.
- Avoid pretending missing code is visible.

Output format:
1. Likely behavior
2. Directly supported observations
3. Inferences
4. What cannot be determined from the snippet alone

Partial context:
{{PARTIAL_CONTEXT}}
```

---

## T6 Pseudocode / Structured Explanation

```text
You are analyzing C source code for benchmark item {{PROGRAM_ID}}.

Task: rewrite the key logic as pseudocode or a structured explanation.

Requirements:
- Preserve semantics.
- Do not invent helper functions that are not implied by the code.
- Keep the pseudocode readable and faithful to control flow.

Output format:
1. Scope statement
2. Pseudocode
3. Notes on approximations

Source:
{{SOURCE_CODE}}
```

---

## T7 Correctness / Risk Review

```text
You are reviewing C source code for benchmark item {{PROGRAM_ID}}.

Task: identify confirmed bugs if they exist, otherwise justify a low-bug-risk assessment and call out any correctness or safety risks that remain worth reviewing.

Requirements:
- Prioritize correctness and safety findings.
- Separate confirmed bugs from lower-confidence risks and from "no confirmed bug" conclusions.
- For each finding, cite the relevant code pattern and explain the impact.
- If you conclude there is no confirmed bug, explain why the code appears low-risk rather than inventing a bug.
- Do not report style nits unless they matter to correctness or safety.

Output format:
1. Confirmed bugs or "no confirmed bug"
2. Residual correctness or safety risks
3. Why each finding is a bug or risk
4. Conditions required to trigger it
5. Confidence and uncertainty

Source:
{{SOURCE_CODE}}
```

---

## T9 Intent Mapping

```text
You are analyzing C source code for benchmark item {{PROGRAM_ID}}.

Task: map source structure to intended behavior.

Requirements:
- Connect concrete source elements to likely user-visible or system-visible intent.
- If a reference specification is provided, compare the implementation against it.
- Distinguish confirmed alignment from inferred alignment.

Output format:
1. Intended behaviors
2. Source elements that implement each behavior
3. Mismatches or missing implementation
4. Uncertainties

Reference specification:
{{REFERENCE_SPEC}}

Source:
{{SOURCE_CODE}}
```

---

## T10 Test-Case / Input Synthesis

```text
You are analyzing C source code for benchmark item {{PROGRAM_ID}}.

Task: propose test cases or input classes that would exercise the program meaningfully.

Requirements:
- Cover the main path plus important edge cases.
- Include failure or boundary conditions when relevant.
- Keep the tests behavior-driven, not line-coverage-driven only.

Output format:
1. Normal-case tests
2. Edge-case tests
3. Error-case tests
4. Why these tests matter

Source:
{{SOURCE_CODE}}
```

---

## Reporting Prompt

Use this when converting raw task outputs into a concise benchmark report:

```text
Summarize the benchmark run for {{PROGRAM_ID}}.

Include:
- task name
- condition metadata
- main strengths
- main errors
- final score if provided
- one sentence on likely failure mode
```
