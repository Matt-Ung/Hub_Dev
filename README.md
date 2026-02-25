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
- Copy Procmon + Wireshark into VM; set required permissions/config (Vagrant)
- Build a pyghidra-based tool to interact with a Ghidra program (“Script Execution”)
- Automate the spawning of the servers?
  - Maybe a txt json file of the available MCP servers and a flag in running client to run them on start if enabled
 
Todo:
Vagrant, (https://portal.cloud.hashicorp.com/vagrant/discover?query=windows-11)
Fine grained or run cmds and figure out flags


## Goals for Feb 25
- Schedule defense
- Define metrics/gameplan for quantifying tool effectiveness
- Build debugger/anti-analysis parser (timing checks, `IsDebuggerPresent`, `INT 3`, PEB `BeingDebugged`)
- Set up multi-agent structure + improve prompting

Test binaries: RE Challenges, packing, golang, string takss

Start making different agents 
Program do, make yara signature unique,

Pydantic agent- deep

Subagent from text, How it creates sub agents, 
- Skills, tool
- context windows Quadratic

Test Performance 

UPX, string obfuscation

## Goals for Mar 4, 11, 18
- TBD

## By Mar 20
- Close out tool development
- Begin testing on tool effectiveness
- Begin drafting thesis write-up
