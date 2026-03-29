# Alternate Model MCP

## Purpose

`modelGatewayMCP.py` adds a separate model-access tool lane to the repo. It is not a replacement for the main deep-agent model path. Instead, it gives the agent a way to call alternate backends when a different model family is useful.

This is the intended role:

- keep the main pipeline on the current default provider path
- let workers selectively call a secondary model through MCP
- treat that secondary model as advisory

## Supported Backends

### `openai_compatible`

Use for:

- self-hosted `vLLM`
- `llama.cpp` OpenAI-style servers
- Runpod or similar GPU endpoints that expose `/v1/chat/completions`
- other hosted inference servers that mimic the OpenAI chat-completions API

Relevant env vars:

- `OPENAI_COMPAT_MODEL_ID`
- `OPENAI_COMPAT_BASE_URL`
- `OPENAI_COMPAT_API_KEY`

### `huggingface_inference`

Use for:

- Hugging Face hosted Inference API
- simple Hugging Face-style generation endpoints

Relevant env vars:

- `HF_MODEL_ID`
- `HF_INFERENCE_ENDPOINT`
- `HF_INFERENCE_API_TOKEN`

## Tool Surface

- `listAltModelBackends()`
- `generateWithAltModel(...)`
- `classifyWithAltModel(...)`
- `compareModelOutputs(...)`
- `recoverDecompilationWithAltModel(...)`

## When To Use It

Good fits:

- comparing two candidate explanations or reports
- malware-family or style classification
- generating better names or type hypotheses from decompiler output
- asking an open-weight code model to clean up source-like logic from a dense pseudocode snippet

Bad fits:

- replacing Ghidra metadata, strings, imports, xrefs, or other deterministic facts
- acting as the only evidence source for high-confidence malware claims

## Paper-Inspired Use

The IDIOMS paper frames neural models as an additional layer on top of deterministic decompiler output, especially for:

- improving source-like readability
- recovering type information
- proposing better names and higher-level structure

That is exactly how this MCP server should be used in this repo: as a bounded helper layered on top of Ghidra and static-analysis artifacts, not as a standalone oracle.

## Example Flow

1. Use `ghidramcp` to decompile a relevant function and gather nearby strings/xrefs/imports.
2. Call `recoverDecompilationWithAltModel(...)` with the decompiled snippet and short context.
3. Treat returned names/types as suggestions.
4. Validate them against concrete static artifacts before turning them into findings or queueing edits.

## Example Calls

For decompiler cleanup:

```text
recoverDecompilationWithAltModel(
  decompiled_code="<Ghidra pseudocode here>",
  surrounding_context="Imports: OpenProcess, TerminateProcess. Strings: Error, Invalid command.",
  provider="openai_compatible",
  model="Qwen/Qwen2.5-Coder-7B-Instruct"
)
```

For a lightweight family/style judgment:

```text
classifyWithAltModel(
  text="<concise sample summary here>",
  labels=["loader", "config_decoder", "anti_analysis", "dispatch_stub"],
  task_instruction="Choose the best behavioral category for this sample."
)
```
