# Progress Log

## Evaluation Docs

- Binary- and workflow-oriented testing plan: `Testing/TESTING_PLAN.md`
- Source-code evaluation framework: `Testing/C_Source_Evaluation/README.md`
- Source-eval prompt library: `Testing/C_Source_Evaluation/prompt_library/`

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

TESTING:
Query: Can you perform analysis on the program in ghidra as a whole? Try to get an understanding of the control flow of the program and what it is doing and provide a brief report with analysis. Use tools capa and floss to deduce forms of obfuscation.
Task: Using all the information gathered and provide an explanation of obfuscation techniques and the program purpose

Excercises to do: experimental data

UPX packed:
Experiments:
binwalk? 
yara, generate yara sigs and testing
different tools in conjunction,
declaring structs, patching, deobfuscation int 3
Hook into auto-analyze
suggest, ask for approval when loaded,
Start generating setup guide as well


### Final Analysis Report on `winapi_behavior_test.exe`

#### 1. Program Context
- **Executable Name:** `winapi_behavior_test.exe`
- **Architecture:** AMD64, Little Endian
- **Compiler:** MinGW (GNU)
- **File Hashes:**
  - **MD5:** `dfb9668cc69c5770fba6f4603b7a79aa`
  - **SHA256:** `42b96f63d3da26023fa807965ed975f8cc2e9c7494e25445db3815fd9fbdc9cd`

#### 2. Memory Structure
The binary consists of several segments relevant for execution:
- **.text Segment:** Contains executable code.
- **.data Segment:** Stores initialized data.
- **.rdata Segment:** Contains read-only data.
- **.bss Segment:** Holds uninitialized data.
- **.idata Segment:** Manages import data for external libraries.

#### 3. Control Flow and Functionality
- The executable employs functions associated with Windows graphical user interface (GUI) management and process control, such as `CreateMutexA` and `GetProcAddress`, indicating capabilities for dynamic user interactions and multitasking.
- The ability to handle memory management and create synchronization objects (mutexes) suggests a design focused on robust operational integrity.

#### 4. Identified Obfuscation Techniques
1. **Dynamic Command Execution:**
   - The program can execute shell commands (notably `CMD: cmd.exe /c echo hello`), revealing functionality typical of software designed to operate dynamically within its environment, often characteristic of obfuscated or malicious applications.

2. **Robust Error Management:**
   - The presence of numerous structured error messages demonstrates a design aimed at maintaining functionality under various execution conditions, reflecting stealthy behavior consistent with malware practices.

3. **Use of Shared Libraries:**
   - The executable links dynamically to shared modules, which not only allows flexibility but also complicates static analysis, commonly employed by obfuscated code to obscure true intentions.

4. **Obfuscated Functionality:**
   - The detection of string encoding or dynamic string generation methods indicates possible obfuscation used to conceal specific actions, enhancing evasion from static analysis tools.

#### 5. Conclusive Intent
The operational capabilities and behaviors observed in `winapi_behavior_test.exe` suggest a dual nature: it might serve benign functionalities while also possessing attributes commonly associated with malicious software, particularly regarding dynamic command execution and process management.

### Recommendations for Future Analysis
- **Live Monitoring:** Conduct real-time analysis to observe execution behaviors and decision-making processes, yielding deeper insights into the program's intent.
- **Behavioral Auditing:** Implement continuous observation across diverse environments to establish a consistent operational profile, particularly assessing behavior variations in different contexts.

This consolidated understanding emphasizes the necessity of cautious deployment and vigilant monitoring when dealing with executables of this nature.

Output: [18:02:21] Chat turn finished in 409.4s (mode=classic)

## Goals for Mar 4, 11, 18
- TBD

## By Mar 20
- Close out tool development
- Begin testing on tool effectiveness
- Begin drafting thesis write-up

Test binaries: RE Challenges, packing, golang, string takss

Start making different agents 
Program do, make yara signature unique,

Pydantic agent- deep

Subagent from text, How it creates sub agents, 
- Skills, tool
- context windows Quadratic

Test Performance 
yara rules
UPX, string obfuscation

Start testing with labs: OS Lab

Figure out: 
Change agent config, 
config -> task:

Correct functions identify
Decompilation agent 
Start thinking of agent configs & instructions
Remove start-up code, decompile whole program

toplogies & prompts
What doesnj't/does work.

How does it decide which tool?

Screnshots logs: Experiment documetnation
Skills? System prompting what works better, what context is necessary
