# Config Decoder Test

> Status: reviewed_concrete_anchor_v1
> Concrete reviewed anchors intended for stable evaluation and reproducible judging.

## Program Summary

This program decodes a single-byte XOR configuration blob with key 0x4B, parses three key=value lines, and stores the recovered values into ParsedConfig.path, ParsedConfig.port, and ParsedConfig.flag.

## Why It Matters

- This is the simplest non-trivial encoding pattern that FLOSS is designed to recover.  If the analysis pipeline's FLOSS integration cannot produce the decoded config strings, either the tool call is wrong or the agent is not inspecting FLOSS output.  The config values (path, port, flag) serve as concrete "expected evidence" entries in the scoring rubric. The parsing logic adds branching complexity beyond a simple decode loop, giving the planner meaningful work items (decode routine vs. parser vs. validation).

## Primary Techniques

- xor_decode copies ENCODED_CONFIG into a local decoded buffer using XOR key 0x4B
- parse_config splits the decoded buffer on '\n' and routes each line to parse_line
- parse_line recognizes the keys path, port, and flag and validates the port as digits only
- The recovered configuration values are printed back to stdout

## Expected Analysis Signals

- Recover C:\ProgramData\agent\config.ini from the decoded config
- Recover port 8443 and flag persist=true
- Identify CONFIG_XOR_KEY as 0x4B
- Explain that malformed numeric port values cause parse_line to return -1

## Autodetected Key Functions

- `xor_decode`: decode or deobfuscation helper
- `parse_line`: autodetected helper function
- `parse_config`: initialization or configuration
- `main`: entry point and orchestration

## Recommended Tooling

- `flareflossmcp`
- `stringmcp`
- `ghidramcp`
- `CapaMCP`

## Related Binary Variants

- `config_decoder_test.exe`
