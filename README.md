# Progress Log

## Work from Feb 5–11
### Gradio integration
- Integrated Gradio (baseline wiring / UI scaffold)
### Tooling
- HashDB Lookup: Done
- VM Spawning & Execution: In progress  
  - Blockers: `VBoxManage` ISO workflow; snapshot-load permissions
- Script Execution: In progress  
  - Resource: https://pypi.org/project/pyghidra/

## Goals for Feb 18
- Resolve permissions model for VM instances + ISO image handling; define ISO workflow (source/storage/automation)
- Copy Procmon + Wireshark into VM; set required permissions/config
- Build a pyghidra-based tool to interact with a Ghidra program (“Script Execution”)

## Goals for Feb 25
- Schedule defense
- Define metrics/gameplan for quantifying tool effectiveness
- Build debugger/anti-analysis parser (timing checks, `IsDebuggerPresent`, `INT 3`, PEB `BeingDebugged`)
- Set up multi-agent structure + improve prompting

## By Mar 20
- Close out tool development
- Begin testing on tool effectiveness
- Begin drafting thesis write-up
